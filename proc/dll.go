package proc

import (
	"fmt"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (p *Proc) InjectDLL(dllPath string) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	pathUTF16, err := windows.UTF16FromString(dllPath)
	if err != nil {
		return err
	}
	pathBytes := unsafe.Slice((*byte)(unsafe.Pointer(&pathUTF16[0])), len(pathUTF16)*2)

	procVirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	remoteMem, _, err := procVirtualAllocEx.Call(
		uintptr(p.handle),
		0,
		uintptr(len(pathBytes)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if remoteMem == 0 {
		return err
	}
	slog.Debug("allocated memory for dll path", "ret", err)

	procVirtualFreeEx := kernel32.NewProc("VirtualFreeEx")
	defer func() {
		ret, _, err := procVirtualFreeEx.Call(uintptr(p.handle), remoteMem, 0, windows.MEM_RELEASE)
		if ret == 0 {
			slog.Warn("failed to free remote memory", "err", err)
		}
	}()

	_, err = p.write(remoteMem, &pathBytes[0], uintptr(len(pathBytes)))
	if err != nil {
		return err
	}
	slog.Debug("wrote dll path")

	procCreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
	procLoadLibraryW := kernel32.NewProc("LoadLibraryW")
	slog.Debug("creating remote thread")
	remoteThread, _, err := procCreateRemoteThread.Call(
		uintptr(p.handle),
		0,
		0,
		procLoadLibraryW.Addr(),
		remoteMem,
		0,
		0,
	)
	if remoteThread == 0 {
		return err
	}
	remoteThreadHandle := windows.Handle(remoteThread)
	defer windows.CloseHandle(remoteThreadHandle)

	event, err := windows.WaitForSingleObject(remoteThreadHandle, windows.INFINITE)
	if err != nil {
		return err
	}
	slog.Debug("remote thread finished", "event", event)

	exitCode, err := getExitCodeThread(kernel32, remoteThreadHandle)
	if err != nil {
		return err
	}
	if exitCode == 0 {
		return fmt.Errorf("LoadLibraryW failed in remote process")
	}

	return nil
}

func (p *Proc) EjectDLL(handle windows.Handle) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	procCreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
	procFreeLibrary := kernel32.NewProc("FreeLibrary")
	remoteThread, _, err := procCreateRemoteThread.Call(
		uintptr(p.handle),
		0,
		0,
		procFreeLibrary.Addr(),
		uintptr(handle),
		0,
		0,
	)
	if remoteThread == 0 {
		return err
	}
	remoteThreadHandle := windows.Handle(remoteThread)
	defer windows.CloseHandle(remoteThreadHandle)

	if _, err := windows.WaitForSingleObject(remoteThreadHandle, windows.INFINITE); err != nil {
		return err
	}

	exitCode, err := getExitCodeThread(kernel32, remoteThreadHandle)
	if err != nil {
		return err
	}
	if exitCode == 0 {
		return fmt.Errorf("FreeLibrary failed in remote process")
	}

	slog.Debug("freed library", "exitCode", exitCode)

	return nil
}

func getExitCodeThread(kernel32 *windows.LazyDLL, handle windows.Handle) (uint32, error) {
	procGetExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	var exitCode uint32
	ret, _, err := procGetExitCodeThread.Call(uintptr(handle), uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		return 0, err
	}
	return exitCode, nil
}
