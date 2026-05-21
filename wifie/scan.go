package wifie

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ScanNetworks(iface string, timeout time.Duration, channels []int) (*ScanResult, error) {
	result := &ScanResult{
		Networks: make([]*WiFiNetwork, 0),
		Stations: make([]*WiFiStation, 0),
	}

	start := time.Now()

	if len(channels) > 0 {
		for _, ch := range channels {
			SetChannel(iface, ch)
			networks, err := passiveScanChannel(iface, ch, min(timeout/2, 3*time.Second), result)
			if err == nil {
				result.Networks = networks
			}
			time.Sleep(time.Duration(200) * time.Millisecond)
		}
	} else {
		ch := GetCurrentChannel(iface)
		if ch == 0 {
			ch = 1
		}
		networks, err := passiveScanChannel(iface, ch, timeout, result)
		if err == nil {
			result.Networks = networks
		}
	}

	result.Duration = time.Since(start).Seconds()
	return result, nil
}

func passiveScanChannel(iface string, channel int, timeout time.Duration, result *ScanResult) ([]*WiFiNetwork, error) {
	SetChannel(iface, channel)

	_ = result

	output, err := exec.Command("timeout", fmt.Sprintf("%.0f", timeout.Seconds()),
		"tcpdump", "-i", iface, "-c", "100", "-w", "-", "type mgt subtype beacon or type mgt subtype probe-resp").Output()

	if err != nil {
		output, err = exec.Command("timeout", fmt.Sprintf("%.0f", timeout.Seconds()),
			"tcpdump", "-i", iface, "-c", "50", "-w", "-").Output()
		if err != nil {
			return nil, fmt.Errorf("wifie: scan failed: %w", err)
		}
	}

	_ = output
	return nil, fmt.Errorf("wifie: scan: use ScanCallbacks for live capture")
}

func LiveScan(iface string, timeout time.Duration, channels []int, callback func(*WiFiNetwork)) error {
	if IsMonitorMode(iface) {
		return liveScanMonitor(iface, timeout, channels, callback)
	}
	return liveScanManaged(iface, timeout, callback)
}

func LiveScanWithHandshake(iface string, timeout time.Duration, channels []int, networkCallback func(*WiFiNetwork), handshakeCallback func(*WPAHandshake)) error {
	if !IsMonitorMode(iface) {
		return fmt.Errorf("wifie: handshake capture requires monitor mode")
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	if len(channels) > 0 {
		go ChannelHop(iface, ChannelHopConfig{Channels: channels, HopDelay: DEFAULT_HOPFREQ}, stopCh)
	}

	handshakes := make(map[string]*WPAHandshake)
	seenNetworks := make(map[string]bool)

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		output, err := exec.Command("timeout", "2",
			"tcpdump", "-i", iface, "-c", "20",
			"-e", "-l", "type mgt subtype beacon or type mgt subtype probe-resp or wlan addr2").Output()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		networks := parseTcpDumpOutput(string(output))
		for _, net := range networks {
			if !seenNetworks[net.BSSID] {
				seenNetworks[net.BSSID] = true
				networkCallback(net)
			}
		}

		_ = handshakes
	}

	return nil
}

func CaptureHandshake(iface string, bssid string, timeout time.Duration, channel int) (*WPAHandshake, error) {
	if !IsMonitorMode(iface) {
		monIface, err := EnableMonitorMode(iface)
		if err != nil {
			return nil, err
		}
		defer DisableMonitorMode(monIface)
		iface = monIface
	}

	if channel > 0 {
		SetChannel(iface, channel)
	}

	cfg := CaptureConfig{
		Iface:   iface,
		BSSID:   bssid,
		Channel: channel,
		Timeout: timeout,
	}
	return ListenForHandshake(cfg)
}

func ScanPcapFile(filename string, callback func(*WiFiNetwork, *WPAHandshake)) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("wifie: read pcap: %w", err)
	}

	hdr, offset, err := ParsePcapHeader(data)
	if err != nil {
		return err
	}

	linktype := int(hdr.Network)
	seenNetworks := make(map[string]*WiFiNetwork)
	handshakes := make(map[string]*WPAHandshake)

	var parseErr error
	err = ParsePcapFile(data, linktype, func(frame *Frame80211, ts time.Time) error {
		if frame.Subtype == IEEE80211_FC0_SUBTYPE_BEACON || frame.Subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP {
			net := ParseBeacon(frame)
			if net != nil {
				if existing, ok := seenNetworks[net.BSSID]; ok {
					existing.LastSeen = ts.Unix()
					existing.BeaconCount++
				} else {
					net.FirstSeen = ts.Unix()
					net.LastSeen = ts.Unix()
					net.BeaconCount = 1
					seenNetworks[net.BSSID] = net
				}
			}
		}

		if frame.Type == IEEE80211_FC0_TYPE_DATA && frame.Protected {
			bssid := GetBSSID(frame)
			if bssid == "" {
				return nil
			}

			if _, ok := handshakes[bssid]; !ok {
				handshakes[bssid] = &WPAHandshake{}
			}
			DetectWPAHandshake(frame, handshakes[bssid])
		}
		return nil
	})

	if err != nil && parseErr == nil {
		parseErr = err
	}
	_ = offset

	for _, net := range seenNetworks {
		if callback != nil {
			callback(net, nil)
		}
	}

	for _, hs := range handshakes {
		if hs.Complete {
			if callback != nil {
				callback(nil, hs)
			}
		}
	}

	return parseErr
}

func liveScanMonitor(iface string, timeout time.Duration, channels []int, callback func(*WiFiNetwork)) error {
	stopCh := make(chan struct{})

	if len(channels) > 0 {
		channelsCopy := make([]int, len(channels))
		copy(channelsCopy, channels)
		go ChannelHop(iface, ChannelHopConfig{Channels: channelsCopy, HopDelay: 400}, stopCh)
	}

	seen := make(map[string]bool)

	cfg := CaptureConfig{
		Iface:   iface,
		Timeout: timeout,
	}

	session, err := StartNativeCapture(cfg,
		func(frame *Frame80211, ts time.Time) {
			if frame.Subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
				frame.Subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP {
				net := ParseBeacon(frame)
				if net != nil && !seen[net.BSSID] {
					seen[net.BSSID] = true
					callback(net)
				}
			}
		},
		nil,
	)
	if err != nil {
		close(stopCh)
		return fmt.Errorf("wifie: live scan: %w", err)
	}

	time.Sleep(timeout)
	session.Stop()
	close(stopCh)
	return nil
}

func liveScanManaged(iface string, timeout time.Duration, callback func(*WiFiNetwork)) error {
	output, err := exec.Command("timeout", fmt.Sprintf("%.0f", timeout.Seconds()),
		"iwlist", iface, "scan").Output()
	if err != nil {
		return fmt.Errorf("wifie: iwlist scan: %w", err)
	}

	networks := parseIwlistOutput(string(output))
	for _, net := range networks {
		callback(net)
	}
	return nil
}

func parseTcpDumpOutput(output string) []*WiFiNetwork {
	var networks []*WiFiNetwork
	lines := strings.Split(output, "\n")

	var currentNet *WiFiNetwork

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Beacon (") || strings.Contains(line, "Probe Response (") {
			if currentNet != nil && currentNet.BSSID != "" {
				networks = append(networks, currentNet)
			}
			currentNet = &WiFiNetwork{
				InfoElements: make(map[int][]byte),
			}

			bssidRe := regexp.MustCompile(`SA:([0-9a-fA-F:]{17})`)
			if matches := bssidRe.FindStringSubmatch(line); len(matches) >= 2 {
				currentNet.BSSID = matches[1]
			}

			signalRe := regexp.MustCompile(`(-\d+)dBm`)
			if matches := signalRe.FindStringSubmatch(line); len(matches) >= 2 {
				signal, _ := strconv.Atoi(matches[1])
				currentNet.Signal = signal
			}
		} else if currentNet != nil {
			essidRe := regexp.MustCompile(`SSID:\s*(.+)`)
			if matches := essidRe.FindStringSubmatch(line); len(matches) >= 2 {
				currentNet.ESSID = strings.TrimSpace(matches[1])
			}

			chRe := regexp.MustCompile(`Channel:\s*(\d+)`)
			if matches := chRe.FindStringSubmatch(line); len(matches) >= 2 {
				ch, _ := strconv.Atoi(matches[1])
				currentNet.Channel = ch
				currentNet.Freq = FreqFromChannel(ch)
			}

			rateRe := regexp.MustCompile(`(\d+\.?\d*)\*?\s*(Mb/s|Mbps)`)
			if matches := rateRe.FindStringSubmatch(line); len(matches) >= 2 {
				rate, _ := strconv.ParseFloat(matches[1], 64)
				if rate > currentNet.MaxRate {
					currentNet.MaxRate = rate
				}
			}
		}
	}

	if currentNet != nil && currentNet.BSSID != "" {
		networks = append(networks, currentNet)
	}

	return networks
}

func parseIwlistOutput(output string) []*WiFiNetwork {
	var networks []*WiFiNetwork
	cells := strings.Split(output, "Cell ")

	for _, cell := range cells[1:] {
		net := &WiFiNetwork{
			InfoElements: make(map[int][]byte),
		}

		addrRe := regexp.MustCompile(`Address:\s*([0-9A-Fa-f:]{17})`)
		if matches := addrRe.FindStringSubmatch(cell); len(matches) >= 2 {
			net.BSSID = matches[1]
		}

		chRe := regexp.MustCompile(`Channel:(\d+)`)
		if matches := chRe.FindStringSubmatch(cell); len(matches) >= 2 {
			ch, _ := strconv.Atoi(matches[1])
			net.Channel = ch
			net.Freq = FreqFromChannel(ch)
		}

		freqRe := regexp.MustCompile(`Frequency:(\d+\.?\d*)\s*GHz`)
		if matches := freqRe.FindStringSubmatch(cell); len(matches) >= 2 {
			freq, _ := strconv.ParseFloat(matches[1], 64)
			net.Freq = int(freq * 1000)
			net.Channel = FreqToChannel(net.Freq)
		}

		signalRe := regexp.MustCompile(`Signal level[=:]?\s*(-?\d+)\s*dBm`)
		if matches := signalRe.FindStringSubmatch(cell); len(matches) >= 2 {
			signal, _ := strconv.Atoi(matches[1])
			net.Signal = signal
		}

		essidRe := regexp.MustCompile(`ESSID:"([^"]*)"`)
		if matches := essidRe.FindStringSubmatch(cell); len(matches) >= 2 {
			net.ESSID = matches[1]
		}

		if strings.Contains(cell, "Encryption key:on") {
			net.Privacy = true
		}

		if strings.Contains(cell, "WPA2") {
			net.Standard = "WPA2"
		} else if strings.Contains(cell, "WPA") {
			net.Standard = "WPA"
		} else if net.Privacy {
			net.Standard = "WEP"
		} else {
			net.Standard = "Open"
		}

		if strings.Contains(cell, "TKIP") {
			net.Cipher = "TKIP"
		}
		if strings.Contains(cell, "CCMP") {
			net.Cipher = "CCMP"
		}
		if strings.Contains(cell, "AES") {
			net.Cipher = "CCMP"
		}
		if strings.Contains(cell, "PSK") {
			net.Auth = "PSK"
		}
		if strings.Contains(cell, "802.1x") || strings.Contains(cell, "802.1X") {
			net.Auth = "MGT"
		}

		signalRe2 := regexp.MustCompile(`Quality=(\d+)/\d+`)
		if matches := signalRe2.FindStringSubmatch(cell); len(matches) >= 2 {
			quality, _ := strconv.Atoi(matches[1])
			net.Signal = quality*2 - 100
		}

		networks = append(networks, net)
	}

	return networks
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}