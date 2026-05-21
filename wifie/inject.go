package wifie

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

func InjectPacket(iface string, packet []byte) error {
	if !IsMonitorMode(iface) {
		return fmt.Errorf("wifie: inject: interface %s must be in monitor mode", iface)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("wifie: inject socket: %w", err)
	}
	defer syscall.Close(fd)

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("wifie: inject: get interface %s: %w", iface, err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: Htons(syscall.ETH_P_ALL),
		Ifindex:  ifaceObj.Index,
		Halen:    6,
	}

	err = syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return fmt.Errorf("wifie: inject send: %w", err)
	}

	return nil
}

func InjectFrame(iface string, frame []byte) error {
	return InjectPacket(iface, frame)
}

func SendProbeRequest(iface string, bssid string) error {
	var probeTemplate = []byte{
		0x40, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x00,
		0x00, 0x00,
	}

	probe := make([]byte, len(probeTemplate))
	copy(probe, probeTemplate)

	copy(probe[10:16], parseMACBytes(bssid))

	probe = append(probe, Standard80211Rates...)

	return InjectPacket(iface, probe)
}

func InjectBroadcastDeauth(iface, bssid, transmitter string, count int) error {
	for i := 0; i < count; i++ {
		packet := BuildDeauthPacket(bssid, "FF:FF:FF:FF:FF:FF", transmitter, 7)
		if err := InjectPacket(iface, packet); err != nil {
			return err
		}
	}
	return nil
}

func InjectTargetedDeauth(iface, bssid, client, transmitter string, count int) error {
	for i := 0; i < count; i++ {
		packet := BuildDeauthPacket(bssid, client, transmitter, 7)
		if err := InjectPacket(iface, packet); err != nil {
			return err
		}
	}
	return nil
}

func StartAireplayDeauth(iface, bssid, client string, count int) (*DeauthResult, error) {
	return SendDeauth(iface, bssid, client, count)
}

func Htons(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}

func InjectViaExec(iface string, packet []byte) error {
	cmd := exec.Command("file2air", "-i", iface, "-")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(packet)
	}()

	return cmd.Run()
}