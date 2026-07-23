package proc

import (
	"debug/pe"
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// checkArchMatch fails fast with a clear error if the injector, target
// process, and DLL aren't all the same architecture. CreateRemoteThread
// and cross-bitness memory access otherwise fail with opaque Win32 errors
// (or silently corrupt data) when bitness differs.
func checkArchMatch(handle windows.Handle, dllPath string) error {
	injectorMachine, err := injectorMachineType()
	if err != nil {
		return err
	}

	targetMachine, err := processMachineType(handle)
	if err != nil {
		return fmt.Errorf("error determining target process architecture: %w", err)
	}
	if targetMachine != injectorMachine {
		return fmt.Errorf("architecture mismatch: injector is %s, target process is %s",
			machineName(injectorMachine), machineName(targetMachine))
	}

	dllMachine, err := dllMachineType(dllPath)
	if err != nil {
		return err
	}
	if dllMachine != targetMachine {
		return fmt.Errorf("architecture mismatch: dll is %s, target process is %s",
			machineName(dllMachine), machineName(targetMachine))
	}

	return nil
}

func injectorMachineType() (uint16, error) {
	switch runtime.GOARCH {
	case "386":
		return pe.IMAGE_FILE_MACHINE_I386, nil
	case "amd64":
		return pe.IMAGE_FILE_MACHINE_AMD64, nil
	case "arm64":
		return pe.IMAGE_FILE_MACHINE_ARM64, nil
	default:
		return 0, fmt.Errorf("unsupported injector architecture: %s", runtime.GOARCH)
	}
}

func processMachineType(handle windows.Handle) (uint16, error) {
	var processMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(handle, &processMachine, &nativeMachine); err != nil {
		return 0, err
	}
	// processMachine is non-zero only when the target is running under
	// WOW64 emulation; otherwise its real architecture is nativeMachine.
	if processMachine != 0 {
		return processMachine, nil
	}
	return nativeMachine, nil
}

func dllMachineType(dllPath string) (uint16, error) {
	f, err := pe.Open(dllPath)
	if err != nil {
		return 0, fmt.Errorf("error reading dll headers: %w", err)
	}
	defer f.Close()
	return f.FileHeader.Machine, nil
}

func machineName(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	default:
		return fmt.Sprintf("0x%x", machine)
	}
}
