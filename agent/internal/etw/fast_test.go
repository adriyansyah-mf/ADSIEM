package etw

import (
	"encoding/binary"
	"testing"
)

// Kernel-File Write's user data: ByteOffset (8 bytes), Irp, FileObject,
// FileKey (pointers), IssuingThreadId, IOSize, IOFlags, ExtraFlags (4 bytes).
func TestFastValueReadsAPointer(t *testing.T) {
	for _, ptr := range []int{8, 4} {
		data := make([]byte, 8+3*ptr+16)
		binary.LittleEndian.PutUint64(data, 0x1000) // ByteOffset
		put := func(at int, v uint64) {
			if ptr == 8 {
				binary.LittleEndian.PutUint64(data[at:], v)
			} else {
				binary.LittleEndian.PutUint32(data[at:], uint32(v))
			}
		}
		put(8, 0xAAAA)        // Irp
		put(8+ptr, 0xFFFFE00) // FileObject
		off := 8 + ptr
		if v, ok := fastValue(data, ptr, off); !ok || v != 0xFFFFE00 {
			t.Fatalf("pointer size %d: %#x %t", ptr, v, ok)
		}
		if _, ok := fastValue(data[:off+ptr-1], ptr, off); ok {
			t.Fatalf("pointer size %d: read past the data", ptr)
		}
	}
	if _, ok := fastValue(make([]byte, 64), 8, -1); ok {
		t.Fatal("negative offset")
	}
}
