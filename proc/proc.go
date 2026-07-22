package proc

import (
	"fmt"
	"log/slog"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Proc struct {
	name   string
	pid    uint32
	handle windows.Handle
}

func OpenProc(name string) (*Proc, error) {
	p := Proc{name: name}

	var err error

	p.pid, err = getProcessID(name)
	if err != nil {
		return nil, fmt.Errorf("error getting pid: %v", err)
	}
	slog.Debug("found pid", "pid", p.pid)

	p.handle, err = windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, p.pid)
	if err != nil {
		return nil, fmt.Errorf("error opening process: %v", err)
	}
	slog.Debug("opened process", "handle", p.handle)

	return &p, nil
}

func (p *Proc) Close() error {
	return windows.CloseHandle(p.handle)
}

func getProcessID(processName string) (uint32, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	for {
		err := windows.Process32Next(handle, &entry)
		if err != nil {
			return 0, err
		}

		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, processName) {
			return entry.ProcessID, nil
		}
	}
}

func (p *Proc) GetModuleBase(moduleName string) (uintptr, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, p.pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ModuleEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	for {
		err := windows.Module32Next(handle, &entry)
		if err != nil {
			return 0, err
		}

		name := windows.UTF16ToString(entry.Module[:])
		if strings.EqualFold(name, moduleName) {
			return entry.ModBaseAddr, nil
		}
	}
}

func (p *Proc) ResolveOffsets(base uintptr, offsets ...uintptr) (uintptr, error) {
	if len(offsets) == 0 {
		return base, nil
	}
	var addr uintptr = base
	for _, offset := range offsets[:len(offsets)-1] {
		ptr, err := ReadValue[uintptr](p, addr+offset)
		if err != nil {
			return 0, err
		}
		addr = ptr
	}
	return addr + offsets[len(offsets)-1], nil
}
