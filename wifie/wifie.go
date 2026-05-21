package wifie

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

func EnableInterface(name string) error {
	output, err := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wifie: enable interface %s: %s: %w", name, string(output), err)
	}
	return nil
}

func DisableInterface(name string) error {
	output, err := exec.Command("ip", "link", "set", name, "down").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wifie: disable interface %s: %s: %w", name, string(output), err)
	}
	return nil
}

func SetTXPower(iface string, power int) error {
	output, err := exec.Command("iw", "dev", iface, "set", "txpower", "fixed", fmt.Sprintf("%d", power*100)).CombinedOutput()
	if err != nil {
		output, err = exec.Command("iwconfig", iface, "txpower", fmt.Sprintf("%d", power)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("wifie: set txpower: %s: %w", string(output), err)
		}
	}
	return nil
}

func GetTXPower(iface string) int {
	output, err := exec.Command("iwconfig", iface).Output()
	if err == nil {
		re := regexp.MustCompile(`Tx-Power[=:]?\s*(\d+)\s*dBm`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			power, _ := strconv.Atoi(matches[1])
			return power
		}
	}
	return 0
}

func AvailableWiFiInterfaces() []string {
	var result []string
	nics, err := ListInterfaces()
	if err != nil {
		return result
	}
	for _, nic := range nics {
		result = append(result, nic.Name)
	}
	return result
}

func CheckWiFiCapability(iface string) map[string]bool {
	capabilities := make(map[string]bool)

	output, err := exec.Command("iw", "phy", "phy0", "info").Output()
	if err != nil {
		output, err = exec.Command("iw", "dev", iface, "info").Output()
		if err != nil {
			return capabilities
		}
	}

	outputStr := string(output)

	capabilities["monitor_mode"] = strings.Contains(outputStr, "monitor")
	capabilities["ap_mode"] = strings.Contains(outputStr, "AP") || strings.Contains(outputStr, "ap")
	capabilities["mesh_mode"] = strings.Contains(outputStr, "mesh")
	capabilities["ibss_mode"] = strings.Contains(outputStr, "IBSS") || strings.Contains(outputStr, "ibss")
	capabilities["p2p"] = strings.Contains(outputStr, "P2P") || strings.Contains(outputStr, "p2p")
	capabilities["5ghz"] = strings.Contains(outputStr, "5") && (strings.Contains(outputStr, "MHz") || strings.Contains(outputStr, "5180"))
	capabilities["ht"] = strings.Contains(outputStr, "HT")
	capabilities["vht"] = strings.Contains(outputStr, "VHT")

	return capabilities
}

func RegulatoryInfo() (string, error) {
	output, err := exec.Command("iw", "reg", "get").Output()
	if err != nil {
		return "", fmt.Errorf("wifie: get regulatory info: %w", err)
	}
	return string(output), nil
}