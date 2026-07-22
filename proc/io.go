package proc

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (p *Proc) read(addr uintptr, buf *byte, size uintptr) (uintptr, error) {
	if size == 0 {
		return 0, fmt.Errorf("read size cant be 0")
	}
	var n uintptr
	err := windows.ReadProcessMemory(p.handle, addr, buf, size, &n)
	if err != nil {
		return 0, err
	}
	if n != size {
		return 0, fmt.Errorf("short read: got %d, want %d bytes", n, size)
	}
	return n, nil
}

func (p *Proc) write(addr uintptr, buf *byte, size uintptr) (uintptr, error) {
	if size == 0 {
		return 0, fmt.Errorf("write size cant be 0")
	}
	var n uintptr
	err := windows.WriteProcessMemory(p.handle, addr, buf, size, &n)
	if err != nil {
		return 0, err
	}
	if n != size {
		return 0, fmt.Errorf("short write: wrote %d, want %d bytes", n, size)
	}
	return n, nil
}

func (p *Proc) ReadBytes(addr uintptr, size uintptr) ([]byte, error) {
	buf := make([]byte, size)
	n, err := p.read(addr, &buf[0], size)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (p *Proc) WriteBytes(addr uintptr, buf []byte) error {
	size := uintptr(len(buf))
	_, err := p.write(addr, &buf[0], size)
	if err != nil {
		return err
	}
	return nil
}

func ReadValue[T any](p *Proc, addr uintptr) (T, error) {
	var value T
	size := unsafe.Sizeof(value)
	_, err := p.read(addr, (*byte)(unsafe.Pointer(&value)), size)
	runtime.KeepAlive(&value)
	if err != nil {
		return value, err
	}
	return value, nil
}

func WriteValue[T any](p *Proc, addr uintptr, value T) error {
	size := unsafe.Sizeof(value)
	_, err := p.write(addr, (*byte)(unsafe.Pointer(&value)), size)
	runtime.KeepAlive(&value)
	if err != nil {
		return err
	}
	return nil
}
