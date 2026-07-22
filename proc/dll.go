package proc

import (
	"log/slog"

	"golang.org/x/sys/windows"
)

func (p *Proc) InjectDLL(dllPath string) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	remoteMem, _, err := procVirtualAllocEx.Call(
		uintptr(p.handle),
		0,
		uintptr(len(dllPath)+1),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if remoteMem == 0 {
		return err
	}
	slog.Debug("allocated memory for dll path", "ret", err)

	dllPathBytePtr, err := windows.BytePtrFromString(dllPath)
	if err != nil {
		return err
	}
	_, err = p.write(remoteMem, dllPathBytePtr, uintptr(len(dllPath)+1))
	if err != nil {
		return err
	}
	slog.Debug("wrote dll path")

	procCreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
	procLoadLibraryA := kernel32.NewProc("LoadLibraryA")
	slog.Debug("creating remote thread")
	remoteThreadHandle, _, err := procCreateRemoteThread.Call(
		uintptr(p.handle),
		0,
		0,
		procLoadLibraryA.Addr(),
		remoteMem,
		0,
		0,
	)
	if remoteThreadHandle == 0 {
		return err
	}
	handle := windows.Handle(remoteThreadHandle)
	defer windows.CloseHandle(handle)

	event, err := windows.WaitForSingleObject(handle, windows.INFINITE)
	if err != nil {
		return err
	}
	slog.Debug("remote thread finished", "event", event)

	return nil
}

func (p *Proc) EjectDLL(handle windows.Handle) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	procCreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
	procFreeLibrary := kernel32.NewProc("FreeLibrary")
	remoteThreadHandle, _, err := procCreateRemoteThread.Call(
		uintptr(p.handle),
		0,
		0,
		procFreeLibrary.Addr(),
		uintptr(handle),
		0,
		0,
	)
	if remoteThreadHandle == 0 {
		return err
	}
	defer windows.CloseHandle(windows.Handle(remoteThreadHandle))

	slog.Debug("freed library", "ret", err)

	return nil
}
