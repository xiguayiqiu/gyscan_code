package wifie

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
)

func ListInterfaces() ([]WiFiInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("wifie: list interfaces: %w", err)
	}

	var result []WiFiInterface
	for _, iface := range ifaces {
		wi := WiFiInterface{
			Name:  iface.Name,
			Index: iface.Index,
			IsUp:  iface.Flags&net.FlagUp != 0,
		}
		if iface.HardwareAddr != nil {
			wi.MAC = iface.HardwareAddr.String()
		}

		if isWiFiInterface(iface.Name) {
			wi.Type = "WiFi"
			wi.Channel, wi.Freq, wi.Mode = getIfaceInfo(iface.Name)
			wi.Driver = getDriverInfo(iface.Name)
			wi.IsMonitor = wi.Mode == "Monitor"
			result = append(result, wi)
		}
	}

	return result, nil
}

func GetInterface(name string) (*WiFiInterface, error) {
	nics, err := ListInterfaces()
	if err != nil {
		return nil, err
	}
	for _, nic := range nics {
		if nic.Name == name {
			return &nic, nil
		}
	}
	return nil, fmt.Errorf("wifie: interface %s not found", name)
}

func DefaultWiFiInterface() (*WiFiInterface, error) {
	nics, err := ListInterfaces()
	if err != nil {
		return nil, err
	}
	for _, nic := range nics {
		if nic.Type == "WiFi" && nic.IsUp && nic.MAC != "" {
			return &nic, nil
		}
	}
	return nil, fmt.Errorf("wifie: no WiFi interface found")
}

func isWiFiInterface(name string) bool {
	wiFiPrefixes := []string{"wl", "wlan", "wifi", "ath", "ra"}
	for _, prefix := range wiFiPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	output, err := exec.Command("iwconfig", name, "2>/dev/null").Output()
	if err == nil && strings.Contains(string(output), "IEEE 802.11") {
		return true
	}

	output, err = exec.Command("iw", "dev", name, "info").Output()
	if err == nil && strings.Contains(string(output), "Interface") {
		return true
	}

	return false
}

func getIfaceInfo(name string) (channel int, freq int, mode string) {
	output, err := exec.Command("iwconfig", name).Output()
	if err == nil {
		outputStr := string(output)

		freqRe := regexp.MustCompile(`Frequency:(\d+\.?\d*)\s*(GHz|MHz)?`)
		if matches := freqRe.FindStringSubmatch(outputStr); len(matches) >= 2 {
			var freqFloat float64
			fmt.Sscanf(matches[1], "%f", &freqFloat)
			if len(matches) >= 3 && matches[2] == "GHz" {
				freq = int(freqFloat * 1000)
			} else {
				freq = int(freqFloat)
			}
		}

		chRe := regexp.MustCompile(`Channel[=:]?\s*(\d+)`)
		if matches := chRe.FindStringSubmatch(outputStr); len(matches) >= 2 {
			fmt.Sscanf(matches[1], "%d", &channel)
		}

		modeRe := regexp.MustCompile(`Mode:(\w+)`)
		if matches := modeRe.FindStringSubmatch(outputStr); len(matches) >= 2 {
			mode = matches[1]
		}
	}

	if freq == 0 {
		output, err = exec.Command("iw", "dev", name, "info").Output()
		if err == nil {
			outputStr := string(output)

			chRe := regexp.MustCompile(`channel\s+(\d+)`)
			if matches := chRe.FindStringSubmatch(outputStr); len(matches) >= 2 {
				fmt.Sscanf(matches[1], "%d", &channel)
				freq = FreqFromChannel(channel)
			}

			typeRe := regexp.MustCompile(`type\s+(\w+)`)
			if matches := typeRe.FindStringSubmatch(outputStr); len(matches) >= 2 {
				mode = matches[1]
			}
		}
	}

	return
}

func getDriverInfo(name string) string {
	output, err := exec.Command("ethtool", "-i", name).Output()
	if err == nil {
		driverRe := regexp.MustCompile(`driver:\s*(\S+)`)
		if matches := driverRe.FindStringSubmatch(string(output)); len(matches) >= 2 {
			return matches[1]
		}
	}

	output, err = exec.Command("readlink", fmt.Sprintf("/sys/class/net/%s/device/driver", name)).Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(output)), "/")
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}

	return "unknown"
}

func IsMonitorMode(name string) bool {
	mode := ""
	output, err := exec.Command("iwconfig", name).Output()
	if err == nil {
		modeRe := regexp.MustCompile(`Mode:(\w+)`)
		if matches := modeRe.FindStringSubmatch(string(output)); len(matches) >= 2 {
			mode = matches[1]
		}
	}
	return strings.EqualFold(mode, "Monitor")
}

func EnableMonitorMode(name string) (string, error) {
	if IsMonitorMode(name) {
		return name, nil
	}

	exec.Command("sudo", "ip", "link", "set", name, "down").Run()
	exec.Command("ip", "link", "set", name, "down").Run()

	exec.Command("sudo", "iw", "dev", name, "set", "type", "monitor").Run()
	exec.Command("iw", "dev", name, "set", "type", "monitor").Run()

	exec.Command("sudo", "ip", "link", "set", name, "up").Run()
	exec.Command("ip", "link", "set", name, "up").Run()

	if IsMonitorMode(name) {
		return name, nil
	}

	monName := name + "mon"
	output, err := exec.Command("sudo", "iw", "dev", name, "interface", "add", monName, "type", "monitor").Output()
	if err != nil {
		output, err = exec.Command("iw", "dev", name, "interface", "add", monName, "type", "monitor").Output()
		if err != nil {
			output, err = exec.Command("sudo", "airmon-ng", "start", name).Output()
			if err != nil {
				err = exec.Command("airmon-ng", "start", name).Run()
				if err != nil {
					return name, nil
				}
			}
			_ = output
			monName = name + "mon"
		}
	}

	exec.Command("sudo", "ip", "link", "set", monName, "up").Run()
	exec.Command("ip", "link", "set", monName, "up").Run()
	return monName, nil
}

func DisableMonitorMode(name string) error {
	exec.Command("ip", "link", "set", name, "down").Run()

	if strings.HasSuffix(name, "mon") {
		baseName := strings.TrimSuffix(name, "mon")
		exec.Command("iw", "dev", name, "del").Run()
		exec.Command("ip", "link", "set", baseName, "up").Run()
		return nil
	}

	exec.Command("iw", "dev", name, "set", "type", "managed").Run()
	exec.Command("ip", "link", "set", name, "up").Run()
	return nil
}