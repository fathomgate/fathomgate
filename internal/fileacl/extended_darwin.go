// SPDX-License-Identifier: FSL-1.1-ALv2

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

// struct attrlist is 24 bytes; these fail to compile if attrList is not.
var (
	_ [24 - unsafe.Sizeof(attrList{})]struct{}
	_ [unsafe.Sizeof(attrList{}) - 24]struct{}
)

// attrBufSize holds the header and a kauth_filesec of 160 entries (24 bytes
// each), more than KAUTH_ACL_MAX_ENTRIES (128). Only the header up to the
// entry count is read, so a longer ACL still parses.
const attrBufSize = 4096

// extended calls fgetattrlist(2) on f's descriptor for
// ATTR_CMN_EXTENDED_SECURITY. The syscall package has no fgetattrlist
// wrapper, and a libc call would need cgo or golang.org/x/sys/unix, so
// this uses syscall.Syscall6 with SYS_FGETATTRLIST (228). On darwin that
// is a raw trap, not libc's syscall(): in Go 1.26, syscall_darwin.go
// declares Syscall6 without a body and asm_darwin_arm64.s implements it
// with SVC $0x80 (asm_darwin_amd64.s: SYSCALL, number + 0x2000000); the
// libc trampolines in runtime/sys_darwin.go are used only by the
// generated wrappers. Apple does not promise that ABI. What happens if it
// moves:
//   - an error return (ENOTSUP, EINVAL, ...) reaches the callers, which
//     refuse the file;
//   - a number the kernel no longer has makes it deliver SIGSYS, which
//     the Go runtime treats as fatal on darwin (_SigThrow in
//     runtime/signal_darwin.go): fathomgate crashes, and no token or key
//     is accepted;
//   - a number reused for another call that returns success without
//     filling the buffer leaves a length of 0, which parseAttrBuf refuses.
//
// Every path fails closed. The number and the layout have been stable
// since Mac OS X 10.4.
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
