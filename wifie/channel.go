package wifie

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func SetChannel(iface string, channel int) error {
	if IsMonitorMode(iface) {
		output, err := exec.Command("iw", "dev", iface, "set", "channel", strconv.Itoa(channel)).CombinedOutput()
		if err != nil {
			output, err = exec.Command("iwconfig", iface, "channel", strconv.Itoa(channel)).CombinedOutput()
			if err != nil {
				return fmt.Errorf("wifie: set channel %d: %s: %w", channel, string(output), err)
			}
		}
		return nil
	}

	output, err := exec.Command("iwconfig", iface, "channel", strconv.Itoa(channel)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wifie: set channel %d: %s: %w", channel, string(output), err)
	}
	return nil
}

func SetFrequency(iface string, freq int) error {
	freqStr := fmt.Sprintf("%d", freq)
	if freq > 3000 {
	} else {
		freqStr = fmt.Sprintf("%dM", freq)
	}

	output, err := exec.Command("iw", "dev", iface, "set", "freq", freqStr).CombinedOutput()
	if err != nil {
		output, err = exec.Command("iwconfig", iface, "freq", freqStr).CombinedOutput()
		if err != nil {
			return fmt.Errorf("wifie: set freq %d: %s: %w", freq, string(output), err)
		}
	}
	return nil
}

func GetCurrentChannel(iface string) int {
	output, err := exec.Command("iwconfig", iface).Output()
	if err == nil {
		chRe := regexp.MustCompile(`Channel[=:]?\s*(\d+)`)
		if matches := chRe.FindStringSubmatch(string(output)); len(matches) >= 2 {
			ch, _ := strconv.Atoi(matches[1])
			return ch
		}
		freqRe := regexp.MustCompile(`Frequency:(\d+\.?\d*)\s*(GHz|MHz)?`)
		if matches := freqRe.FindStringSubmatch(string(output)); len(matches) >= 2 {
			var freq float64
			fmt.Sscanf(matches[1], "%f", &freq)
			if len(matches) >= 3 && matches[2] == "GHz" {
				freq *= 1000
			}
			return FreqToChannel(int(freq))
		}
	}

	output, err = exec.Command("iw", "dev", iface, "info").Output()
	if err == nil {
		chRe := regexp.MustCompile(`channel\s+(\d+)`)
		if matches := chRe.FindStringSubmatch(string(output)); len(matches) >= 2 {
			ch, _ := strconv.Atoi(matches[1])
			return ch
		}
	}

	return 0
}

func GetCurrentFrequency(iface string) int {
	ch := GetCurrentChannel(iface)
	if ch > 0 {
		return FreqFromChannel(ch)
	}
	return 0
}

func SupportedChannels24GHz() []int {
	channels := make([]int, 0, len(Channel24GHzFreq))
	for ch := range Channel24GHzFreq {
		channels = append(channels, ch)
	}
	return channels
}

func SupportedChannels5GHz() []int {
	channels := make([]int, 0, len(Channel5GHzFreq))
	for ch := range Channel5GHzFreq {
		channels = append(channels, ch)
	}
	return channels
}

func AllSupportedChannels() []int {
	return append(SupportedChannels24GHz(), SupportedChannels5GHz()...)
}

func ChannelHop(iface string, config ChannelHopConfig, stopCh <-chan struct{}) error {
	if config.HopDelay <= 0 {
		config.HopDelay = DEFAULT_HOPFREQ
	}
	if len(config.Channels) == 0 {
		config.Channels = SupportedChannels24GHz()
	}

	chanCount := len(config.Channels)
	idx := 0
	first := true

	for {
		select {
		case <-stopCh:
			return nil
		default:
			ch := config.Channels[idx%chanCount]

			if calib := config.Channels[((idx+1)/chanCount+idx)%chanCount]; calib == -1 {
				idx++
				continue
			}

			if !first || idx%chanCount == 0 {
				SetChannel(iface, ch)
			}

			idx++
			first = false

			time.Sleep(time.Duration(config.HopDelay) * time.Millisecond)
		}
	}
}

func MultiChannelHop(ifaces []string, config ChannelHopConfig, stopCh <-chan struct{}) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("wifie: no interfaces for channel hopping")
	}
	if config.HopDelay <= 0 {
		config.HopDelay = DEFAULT_HOPFREQ
	}
	if len(config.Channels) == 0 {
		config.Channels = SupportedChannels24GHz()
	}

	chanCount := len(config.Channels)
	ifNum := len(ifaces)
	chIdx := 0
	cardIdx := 0

	for {
		select {
		case <-stopCh:
			return nil
		default:
			for j := 0; j < ifNum; j++ {
				ch := config.Channels[chIdx%chanCount]
				card := ifaces[cardIdx%ifNum]

				chIdx++
				cardIdx++

				if ch != -1 {
					SetChannel(card, ch)
				}
			}

			time.Sleep(time.Duration(config.HopDelay) * time.Millisecond)
		}
	}
}

func GetSupportedChannels(iface string) ([]int, error) {
	output, err := exec.Command("iw", "list").Output()
	if err != nil {
		output, err = exec.Command("iw", "phy", "phy0", "channels").Output()
		if err != nil {
			output, err = exec.Command("iwlist", iface, "channel").Output()
			if err != nil {
				output, err = exec.Command("iw", "dev", iface, "info").Output()
				if err != nil {
					return SupportedChannels24GHz(), nil
				}
			}
		}
	}

	var channels []int
	lines := strings.Split(string(output), "\n")
	chRe := regexp.MustCompile(`\*\s+(\d+)`)
	freqRe := regexp.MustCompile(`(\d+)\s+MHz`)

	for _, line := range lines {
		if matches := chRe.FindStringSubmatch(line); len(matches) >= 2 {
			ch, _ := strconv.Atoi(matches[1])
			channels = append(channels, ch)
		} else if matches := freqRe.FindStringSubmatch(line); len(matches) >= 2 {
			freq, _ := strconv.Atoi(matches[1])
			ch := FreqToChannel(freq)
			if ch > 0 {
				channels = append(channels, ch)
			}
		}
	}

	if len(channels) == 0 {
		return SupportedChannels24GHz(), nil
	}

	return channels, nil
}

func ChannelFrequency(channel int) int {
	return FreqFromChannel(channel)
}