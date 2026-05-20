package bluez

import (
	"syscall"
	"unsafe"
)

const (
	sizeofSockaddrHCI = 6

	BTPROTO_HCI_SOCK = 1
)

type sockaddrHCI struct {
	Family  uint16
	Dev     uint16
	Channel uint16
}

func openHCI(devID int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_BLUETOOTH, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, BTPROTO_HCI_SOCK)
	if err != nil {
		return -1, err
	}

	sa := sockaddrHCI{
		Family:  syscall.AF_BLUETOOTH,
		Dev:     uint16(devID),
		Channel: uint16(HCI_CHANNEL_RAW),
	}

	if err := bindHCI(fd, &sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func bindHCI(fd int, sa *sockaddrHCI) error {
	_, _, e1 := syscall.RawSyscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
	if e1 != 0 {
		return e1
	}
	return nil
}

func closeSocket(fd int) error {
	return syscall.Close(fd)
}

func sendHCICommand(fd int, cmd []byte) error {
	_, err := syscall.Write(fd, cmd)
	return err
}

func recvHCIEvent(fd int, buf []byte) (int, error) {
	return syscall.Read(fd, buf)
}