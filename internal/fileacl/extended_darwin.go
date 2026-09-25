// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package fileacl

import (
	"os"
	"syscall"
	"unsafe"
)

// attrList is struct attrlist of <sys/attr.h>.
type attrList struct {
	bitmapCount uint16
	reserved    uint16
	commonAttr  uint32
	volAttr     uint32
	dirAttr     uint32
	fileAttr    uint32
	forkAttr    uint32
}

// attrBufSize holds the header and a kauth_filesec of 160 entries (24 bytes
// each), more than KAUTH_ACL_MAX_ENTRIES (128). Only the header up to the
// entry count is read, so a longer ACL still parses.
const attrBufSize = 4096

// extended calls fgetattrlist(2) on f's descriptor for
// ATTR_CMN_EXTENDED_SECURITY. syscall.Syscall6 enters the kernel directly
// (the syscall package has no fgetattrlist wrapper, and a libc call would
// need cgo or golang.org/x/sys/unix). The system call number and the
// attribute layout have been stable since Mac OS X 10.4; if a macOS
// release ever refused the call, Extended would return the error and the
// callers would refuse the file, not accept it.
func extended(f *os.File) (bool, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	buf := make([]byte, attrBufSize)
	al := attrList{bitmapCount: attrBitMapCount, commonAttr: attrCmnReturnedAttrs | attrCmnExtendedSecurity}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_FGETATTRLIST, fd,
			uintptr(unsafe.Pointer(&al)),     //nolint:gosec // struct attrlist passed to the kernel for the duration of the call
			uintptr(unsafe.Pointer(&buf[0])), //nolint:gosec // the output buffer, len(buf) bytes
			uintptr(len(buf)), 0, 0)
	}); err != nil {
		return false, err
	}
	if errno != 0 {
		return false, os.NewSyscallError("fgetattrlist", errno)
	}
	return parseAttrBuf(buf)
}
