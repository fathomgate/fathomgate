// SPDX-License-Identifier: Apache-2.0

package fileacl

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"testing"
)

// attrBufSizeForTest is the size of the darwin buffer (attrBufSize), which
// is only compiled on darwin.
const attrBufSizeForTest = 4096

// attrBuf builds what fgetattrlist returns: with an ACL when count is
// non-nil, in host byte order unless swapped.
func attrBuf(count *uint32, swapped bool) []byte {
	ne := binary.NativeEndian
	buf := make([]byte, 256)
	if count == nil {
		ne.PutUint32(buf[0:4], refOffset)
		ne.PutUint32(buf[4:8], attrCmnReturnedAttrs)
		return buf
	}
	const dataOff = 8 // the filesec follows the attrreference_t
	length := uint32(filesecHeader + 4 + 24)
	ne.PutUint32(buf[0:4], refOffset+8+length)
	ne.PutUint32(buf[4:8], attrCmnReturnedAttrs|attrCmnExtendedSecurity)
	ne.PutUint32(buf[refOffset:], dataOff)
	ne.PutUint32(buf[refOffset+4:], length)
	fsec := buf[refOffset+dataOff:]
	magic, n := uint32(kauthFilesecMagic), *count
	if swapped {
		magic, n = bits.ReverseBytes32(magic), bits.ReverseBytes32(n)
	}
	ne.PutUint32(fsec[0:4], magic)
	ne.PutUint32(fsec[filesecHeader-4:], n)
	return buf
}

func TestParseAttrBuf(t *testing.T) {
	t.Parallel()
	u := func(v uint32) *uint32 { return &v }
	for _, tc := range []struct {
		name string
		buf  []byte
		want bool
		err  bool
	}{
		{name: "no ACL", buf: attrBuf(nil, false)},
		{name: "one entry", buf: attrBuf(u(1), false), want: true},
		{name: "one entry, disk byte order", buf: attrBuf(u(1), true), want: true},
		{name: "many entries", buf: attrBuf(u(128), false), want: true},
		{name: "empty ACL", buf: attrBuf(u(0), false)},
		{name: "KAUTH_FILESEC_NOACL", buf: attrBuf(u(kauthFilesecNoACL), false)},
		{name: "zero-length attribute", buf: func() []byte {
			b := attrBuf(u(1), false)
			binary.NativeEndian.PutUint32(b[refOffset+4:], 0)
			return b
		}()},
		{name: "bad magic", buf: func() []byte {
			b := attrBuf(u(1), false)
			binary.NativeEndian.PutUint32(b[refOffset+8:], 0xdeadbeef)
			return b
		}(), err: true},
		{name: "offset past the buffer", buf: func() []byte {
			b := attrBuf(u(1), false)
			binary.NativeEndian.PutUint32(b[refOffset:], 1<<20)
			return b
		}(), err: true},
		{name: "negative offset", buf: func() []byte {
			b := attrBuf(u(1), false)
			binary.NativeEndian.PutUint32(b[refOffset:], 0xfffffff0)
			return b
		}(), err: true},
		{name: "length shorter than the header", buf: func() []byte {
			b := attrBuf(u(1), false)
			binary.NativeEndian.PutUint32(b[refOffset+4:], 8)
			return b
		}(), err: true},
		{name: "short buffer", buf: make([]byte, 8), err: true},
		// A call that returned success without filling the buffer (a
		// reused system call number) must not read as "no ACL".
		{name: "buffer never written", buf: make([]byte, attrBufSizeForTest), err: true},
		{name: "length past the buffer", buf: func() []byte {
			b := attrBuf(nil, false)
			binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)+1))
			return b
		}(), err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAttrBuf(tc.buf)
			if tc.err {
				if !errors.Is(err, errMalformed) {
					t.Fatalf("%v, %v; want errMalformed", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("%v, %v; want %v", got, err, tc.want)
			}
		})
	}
}
