// SPDX-License-Identifier: FSL-1.1-ALv2

// Package fileacl reports whether an open file carries an extended access
// control list: access the mode bits do not show. The owner-only checks on
// listen token files (cmd/fathomgate) and on the audit key and log
// (internal/audit) read the mode bits, and on macOS an ACL entry such as
// "everyone allow read", set with `chmod +a` or inherited from the folder,
// grants access that a mode of 0600 hides (L2 in the security review of
// PR #109).
//
// Only macOS is checked. On Linux a POSIX ACL's mask is the group
// permission bits, so an ACL that grants anyone else access shows up in
// the mode, and the mode checks refuse it. Windows has its own DACL checks.
// Other systems (FreeBSD and illumos NFSv4 ACLs among them) are a residual
// in docs/security/threat-model.md.
//
// The macOS check needs no cgo: it reads ATTR_CMN_EXTENDED_SECURITY with
// fgetattrlist(2), entered by a raw system call through the syscall
// package, on the open descriptor, so the file checked is the file read.
// extended_darwin.go says how each way that call could break fails
// closed. Filesystems that do not store ACLs (SMB and NFS mounts among
// them) report none, whatever the server enforces.
package fileacl

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"os"
)

// Extended reports whether f has an extended ACL with at least one entry.
// An error means the ACL could not be read; callers refuse the file then,
// as they do for an ACL. On systems other than macOS it always reports
// false.
func Extended(f *os.File) (bool, error) { return extended(f) }

// errMalformed is the answer when fgetattrlist returns something that is
// not a kauth_filesec.
var errMalformed = errors.New("fileacl: the file's extended security attribute is not in the expected form")

// Constants of <sys/attr.h> and <sys/kauth.h> (macOS).
const (
	attrBitMapCount         = 5
	attrCmnReturnedAttrs    = 0x80000000
	attrCmnExtendedSecurity = 0x00400000
	kauthFilesecMagic       = 0x012cc16d
	kauthFilesecNoACL       = 0xffffffff
	// filesecHeader is the kauth_filesec up to and including the ACL's
	// entry count: magic, owner GUID, group GUID, entry count.
	filesecHeader = 4 + 16 + 16 + 4
	// refOffset is where the attrreference_t of ATTR_CMN_EXTENDED_SECURITY
	// starts: after the total length and the returned attribute_set_t.
	refOffset = 4 + attrBitMapCount*4
)

// parseAttrBuf reads the buffer fgetattrlist filled for
// ATTR_CMN_RETURNED_ATTRS|ATTR_CMN_EXTENDED_SECURITY: the total length
// (uint32), the returned attribute_set_t (five uint32; its first is the
// common attributes returned), then the attrreference_t of the security
// attribute (int32 offset from itself, uint32 length) and the
// kauth_filesec it points to. The attribute is returned only when the file
// has an ACL; an ACL with no entries, or KAUTH_FILESEC_NOACL as its count,
// grants nothing. The kernel writes host byte order; a filesec in the
// other order (as stored on disk) is read too.
func parseAttrBuf(buf []byte) (bool, error) {
	ne := binary.NativeEndian
	if len(buf) < refOffset {
		return false, errMalformed
	}
	// The kernel always writes the total length, which covers at least
	// itself and the returned attribute set. A length below that, or past
	// the buffer, means the buffer was not filled by fgetattrlist as
	// asked, so it is refused rather than read as "no ACL".
	total := ne.Uint32(buf[0:4])
	if total < refOffset || int64(total) > int64(len(buf)) {
		return false, errMalformed
	}
	if ne.Uint32(buf[4:8])&attrCmnExtendedSecurity == 0 {
		return false, nil
	}
	if len(buf) < refOffset+8 || total < refOffset+8 {
		return false, errMalformed
	}
	off := int64(int32(ne.Uint32(buf[refOffset : refOffset+4]))) //nolint:gosec // attr_dataoffset is an int32 by definition
	n := int64(ne.Uint32(buf[refOffset+4 : refOffset+8]))
	if n == 0 {
		return false, nil
	}
	start := int64(refOffset) + off
	if off < 8 || n < filesecHeader || start+filesecHeader > int64(len(buf)) {
		return false, errMalformed
	}
	fsec := buf[start : start+filesecHeader]
	count := ne.Uint32(fsec[filesecHeader-4:])
	switch ne.Uint32(fsec[0:4]) {
	case kauthFilesecMagic:
	case bits.ReverseBytes32(kauthFilesecMagic):
		count = bits.ReverseBytes32(count)
	default:
		return false, errMalformed
	}
	return count != 0 && count != kauthFilesecNoACL, nil
}
