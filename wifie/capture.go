package wifie

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	AF_PACKET       = 17
	ETH_P_ALL       = 0x0003
	SO_BINDTODEVICE = 25
)

type CaptureConfig struct {
	Iface   string
	BSSID   string
	Channel int
	PcapFile string
	Timeout  time.Duration
	BufSize  int
}

type CaptureSession struct {
	config     CaptureConfig
	stopCh     chan struct{}
	doneCh     chan struct{}
	pcapFile   *os.File
	handshakes map[string]*WPAHandshake
	mu         sync.Mutex
	packetsIn  int64
	startTime  time.Time
}

func (s *CaptureSession) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	<-s.doneCh
}

func (s *CaptureSession) Wait() error {
	<-s.doneCh
	return nil
}

func (s *CaptureSession) Handshakes() map[string]*WPAHandshake {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]*WPAHandshake)
	for k, v := range s.handshakes {
		result[k] = v
	}
	return result
}

func (s *CaptureSession) SavePcap(filename string) error {
	if s.pcapFile != nil {
		if s.pcapFile.Name() == filename {
			return nil
		}
		s.pcapFile.Close()
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	if err := WritePcapHeader(f, LINKTYPE_IEEE802_11_RADIOTAP); err != nil {
		f.Close()
		return err
	}
	s.pcapFile = f
	return nil
}

func (s *CaptureSession) HandshakeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.handshakes)
}

func (s *CaptureSession) GetHandshake(bssid string) *WPAHandshake {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handshakes[bssid]
}

func (s *CaptureSession) PacketsIn() int64 {
	return s.packetsIn
}

func StartNativeCapture(cfg CaptureConfig,
	frameCallback func(*Frame80211, time.Time),
	handshakeCallback func(*WPAHandshake)) (*CaptureSession, error) {

	if cfg.Iface == "" {
		return nil, fmt.Errorf("wifie: interface required")
	}

	cfg.BSSID = strings.ToLower(cfg.BSSID)

	fd, err := syscall.Socket(AF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("wifie: socket: %w", err)
	}

	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, SO_BINDTODEVICE, cfg.Iface); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("wifie: bind to device %s: %w", cfg.Iface, err)
	}

	bufSize := cfg.BufSize
	if bufSize <= 0 {
		bufSize = 65536
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize)

	syscall.SetNonblock(fd, true)

	session := &CaptureSession{
		config:     cfg,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		handshakes: make(map[string]*WPAHandshake),
		startTime:  time.Now(),
	}

	if cfg.PcapFile != "" {
		f, err := os.Create(cfg.PcapFile)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("wifie: create pcap file: %w", err)
		}
		if err := WritePcapHeader(f, LINKTYPE_IEEE802_11_RADIOTAP); err != nil {
			f.Close()
			syscall.Close(fd)
			return nil, fmt.Errorf("wifie: write pcap header: %w", err)
		}
		session.pcapFile = f
	}

	session.doneCh = make(chan struct{})

	go session.captureLoop(fd, frameCallback, handshakeCallback)

	return session, nil
}

func (s *CaptureSession) captureLoop(fd int,
	frameCallback func(*Frame80211, time.Time),
	handshakeCallback func(*WPAHandshake)) {

	defer func() {
		syscall.Close(fd)
		if s.pcapFile != nil {
			s.pcapFile.Close()
		}
		close(s.doneCh)
	}()

	deadline := time.Time{}
	if s.config.Timeout > 0 {
		deadline = time.Now().Add(s.config.Timeout)
	}

	buf := make([]byte, 65536)

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		if s.config.Timeout > 0 && time.Now().After(deadline) {
			return
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		if n <= 0 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		ts := time.Now()
		s.packetsIn++

		if s.pcapFile != nil {
			WritePcapRecord(s.pcapFile, packet, ts)
		}

		frame, err := ParseFrameWithRadiotap(packet)
		if err != nil || frame == nil {
			continue
		}

		if s.config.BSSID != "" {
			bssid := GetBSSID(frame)
			if bssid != s.config.BSSID && frame.Addr1 != s.config.BSSID &&
				frame.Addr2 != s.config.BSSID && frame.Addr3 != s.config.BSSID {
				continue
			}
		}

		if frameCallback != nil {
			frameCallback(frame, ts)
		}

		if frame.Type != IEEE80211_FC0_TYPE_DATA {
			continue
		}

		hs := &WPAHandshake{}
		if DetectWPAHandshake(frame, hs) {
			if hs.BSSID == "" {
				hs.BSSID = GetBSSID(frame)
			}

			s.mu.Lock()
			existing, ok := s.handshakes[hs.BSSID]
			if ok {
				mergeHandshake(existing, hs)
			} else {
				s.handshakes[hs.BSSID] = hs
			}
			updated := s.handshakes[hs.BSSID]
			s.mu.Unlock()

			if updated.Complete && handshakeCallback != nil {
				handshakeCallback(updated)
			}
		}
	}
}

func mergeHandshake(dst, src *WPAHandshake) {
	if dst.State == 0 {
		dst.State = src.State
	}
	if dst.Frame1 == nil && src.Frame1 != nil {
		dst.Frame1 = src.Frame1
		copy(dst.ANonce[:], src.ANonce[:])
		dst.State |= WPA_STATE_ANONCE
	}
	if dst.Frame2 == nil && src.Frame2 != nil {
		dst.Frame2 = src.Frame2
		copy(dst.SNonce[:], src.SNonce[:])
		dst.State |= WPA_STATE_SNONCE
	}
	if (dst.State&WPA_STATE_EAPOLMIC) == 0 && (src.State&WPA_STATE_EAPOLMIC) != 0 {
		copy(dst.EAPOLData[:src.EAPOLSize], src.EAPOLData[:src.EAPOLSize])
		dst.EAPOLSize = src.EAPOLSize
		copy(dst.MIC[:], src.MIC[:])
		dst.Version = src.Version
		dst.State |= WPA_STATE_EAPOLMIC
	}
	if dst.Frame3 == nil && src.Frame3 != nil {
		dst.Frame3 = src.Frame3
		if (dst.State & WPA_STATE_ANONCE) == 0 {
			copy(dst.ANonce[:], src.ANonce[:])
			dst.State |= WPA_STATE_ANONCE
		}
		if (dst.State&WPA_STATE_EAPOLMIC) == 0 && (src.State&WPA_STATE_EAPOLMIC) != 0 {
			copy(dst.EAPOLData[:src.EAPOLSize], src.EAPOLData[:src.EAPOLSize])
			dst.EAPOLSize = src.EAPOLSize
			copy(dst.MIC[:], src.MIC[:])
			dst.Version = src.Version
			dst.State |= WPA_STATE_EAPOLMIC
		}
		if src.PMKID != nil && dst.PMKID == nil {
			dst.PMKID = src.PMKID
		}
	}
	if dst.Frame4 == nil && src.Frame4 != nil {
		dst.Frame4 = src.Frame4
	}
	if dst.STAMAC == "" {
		dst.STAMAC = src.STAMAC
	}
	if dst.BSSID == "" {
		dst.BSSID = src.BSSID
	}

	dst.Complete = dst.State == WPA_STATE_COMPLETE
}

func htons(val uint16) uint16 {
	return (val>>8)&0xff | (val&0xff)<<8
}

func ListenForHandshake(cfg CaptureConfig) (*WPAHandshake, error) {
	var result *WPAHandshake
	resultCh := make(chan *WPAHandshake, 1)

	session, err := StartNativeCapture(cfg,
		func(frame *Frame80211, ts time.Time) {},
		func(hs *WPAHandshake) {
			if hs.Complete {
				select {
				case resultCh <- hs:
				default:
				}
			}
		},
	)
	if err != nil {
		return nil, err
	}
	defer session.Stop()

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result = <-resultCh:
		return result, nil
	case <-timer.C:
		return nil, fmt.Errorf("wifie: handshake capture timeout after %v", timeout)
	}
}