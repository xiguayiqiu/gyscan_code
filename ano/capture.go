package ano

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CaptureConfig struct {
	Iface      string
	SnapLen    int
	Promisc    bool
	Timeout    time.Duration
	BufferSize int
}

func DefaultCaptureConfig() *CaptureConfig {
	return &CaptureConfig{
		SnapLen:    65535,
		Promisc:    true,
		Timeout:    30 * time.Second,
		BufferSize: 1000,
	}
}

type CaptureSession struct {
	config   *CaptureConfig
	sniffer  *Sniffer
	writer   *PcapWriter
	captured int
	started  time.Time
}

func NewCapture(iface string) *CaptureSession {
	return &CaptureSession{
		config: &CaptureConfig{
			Iface:      iface,
			SnapLen:    65535,
			Promisc:    true,
			BufferSize: 1000,
		},
	}
}

func (cs *CaptureSession) WithConfig(cfg *CaptureConfig) *CaptureSession {
	if cfg != nil {
		cs.config = cfg
	}
	return cs
}

func (cs *CaptureSession) WithTimeout(d time.Duration) *CaptureSession {
	cs.config.Timeout = d
	return cs
}

func (cs *CaptureSession) WithFilter(filter string) *CaptureSession {
	cs.sniffer = NewSniffer().
		OnIface(cs.config.Iface).
		WithTimeout(cs.config.Timeout).
		WithFilter(filter)
	return cs
}

func (cs *CaptureSession) SaveTo(path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("ano: capture save: %w", err)
	}
	defer f.Close()

	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".cap") {
		return cs.saveToCap(f)
	}
	return cs.saveToPcap(f)
}

func (cs *CaptureSession) SaveToCap(path string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("ano: capture save cap: %w", err)
	}
	defer f.Close()
	return cs.saveToCap(f)
}

func (cs *CaptureSession) saveToCap(f *os.File) (int, error) {
	hdr := capHeader{
		Magic:    capMagic,
		Version:  capVersion,
		SnapLen:  uint32(cs.config.SnapLen),
		LinkType: 1,
	}

	var buf []byte
	buf = append(buf, uint32Bytes(hdr.Magic)...)
	buf = append(buf, uint16Bytes(hdr.Version)...)
	buf = append(buf, uint32Bytes(hdr.SnapLen)...)
	buf = append(buf, uint32Bytes(hdr.LinkType)...)

	captured := 0
	cs.captured = 0
	cs.started = time.Now()

	s := NewSniffer().
		OnIface(cs.config.Iface).
		WithTimeout(cs.config.Timeout).
		WithCallback(func(pkt *Packet) {
			cs.captured++
			data := pkt.Bytes()
			now := time.Now()
			buf = append(buf, uint32Bytes(uint32(now.Unix()))...)
			buf = append(buf, uint32Bytes(uint32(now.Nanosecond()/1000))...)
			buf = append(buf, uint32Bytes(uint32(len(data)))...)
			buf = append(buf, uint32Bytes(uint32(len(data)))...)
			buf = append(buf, data...)
			captured++
		})

	ch, err := s.Start()
	if err != nil {
		return 0, err
	}

	for range ch {
	}

	f.Write(buf)
	return captured, nil
}

func (cs *CaptureSession) saveToPcap(f *os.File) (int, error) {
	pw := NewPcapWriter(f)
	if err := pw.WriteHeader(); err != nil {
		return 0, fmt.Errorf("ano: capture pcap header: %w", err)
	}

	captured := 0
	cs.captured = 0
	cs.started = time.Now()

	s := NewSniffer().
		OnIface(cs.config.Iface).
		WithTimeout(cs.config.Timeout).
		WithCallback(func(pkt *Packet) {
			cs.captured++
			pw.WritePacket(pkt)
			captured++
		})

	ch, err := s.Start()
	if err != nil {
		return 0, err
	}

	for range ch {
	}

	return captured, nil
}

func (cs *CaptureSession) StreamTo(f *os.File, format string) (<-chan *Packet, error) {
	if format == "cap" {
		return cs.streamToCap(f)
	}
	return cs.streamToPcap(f)
}

func (cs *CaptureSession) streamToCap(f *os.File) (<-chan *Packet, error) {
	hdr := capHeader{
		Magic:    capMagic,
		Version:  capVersion,
		SnapLen:  uint32(cs.config.SnapLen),
		LinkType: 1,
	}
	var buf []byte
	buf = append(buf, uint32Bytes(hdr.Magic)...)
	buf = append(buf, uint16Bytes(hdr.Version)...)
	buf = append(buf, uint32Bytes(hdr.SnapLen)...)
	buf = append(buf, uint32Bytes(hdr.LinkType)...)
	f.Write(buf)

	ch := make(chan *Packet, cs.config.BufferSize)
	cs.sniffer = NewSniffer().
		OnIface(cs.config.Iface).
		WithTimeout(cs.config.Timeout).
		WithCallback(func(pkt *Packet) {
			data := pkt.Bytes()
			now := time.Now()
			var rec []byte
			rec = append(rec, uint32Bytes(uint32(now.Unix()))...)
			rec = append(rec, uint32Bytes(uint32(now.Nanosecond()/1000))...)
			rec = append(rec, uint32Bytes(uint32(len(data)))...)
			rec = append(rec, uint32Bytes(uint32(len(data)))...)
			rec = append(rec, data...)
			f.Write(rec)

			select {
			case ch <- pkt:
			default:
			}
		})

	rawCh, err := cs.sniffer.Start()
	if err != nil {
		close(ch)
		return nil, err
	}

	go func() {
		defer close(ch)
		for range rawCh {
		}
	}()

	return ch, nil
}

func (cs *CaptureSession) streamToPcap(f *os.File) (<-chan *Packet, error) {
	pw := NewPcapWriter(f)
	if err := pw.WriteHeader(); err != nil {
		return nil, fmt.Errorf("ano: capture pcap header: %w", err)
	}

	ch := make(chan *Packet, cs.config.BufferSize)
	cs.sniffer = NewSniffer().
		OnIface(cs.config.Iface).
		WithTimeout(cs.config.Timeout).
		WithCallback(func(pkt *Packet) {
			pw.WritePacket(pkt)
			select {
			case ch <- pkt:
			default:
			}
		})

	rawCh, err := cs.sniffer.Start()
	if err != nil {
		close(ch)
		return nil, err
	}

	go func() {
		defer close(ch)
		for range rawCh {
		}
	}()

	return ch, nil
}

func (cs *CaptureSession) Captured() int {
	return cs.captured
}

func (cs *CaptureSession) Duration() time.Duration {
	if cs.started.IsZero() {
		return 0
	}
	return time.Since(cs.started)
}

func CaptureToFile(iface, path string, timeout time.Duration, count int, filter string) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, fmt.Errorf("ano: capture file: %w", err)
	}
	defer f.Close()

	var pkts []*Packet
	if filter != "" {
		pkts, err = SniffWithFilter(iface, timeout, count, filter)
	} else {
		pkts, err = Sniff(iface, timeout, count)
	}
	if err != nil {
		return 0, err
	}

	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".cap") {
		return len(pkts), DumpCap(path, pkts)
	}
	return len(pkts), SavePcap(path, pkts)
}

func SniffAndSave(iface, path string, timeout time.Duration, count int) (int, error) {
	return CaptureToFile(iface, path, timeout, count, "")
}

func SniffAndAnalyze(iface string, timeout time.Duration, count int) (*AnalysisResult, error) {
	pkts, err := Sniff(iface, timeout, count)
	if err != nil {
		return nil, err
	}
	return AnalyzePackets(pkts, nil), nil
}

func SniffAndAnalyzeWithFilter(iface string, timeout time.Duration, count int, filter string) (*AnalysisResult, error) {
	pkts, err := SniffWithFilter(iface, timeout, count, filter)
	if err != nil {
		return nil, err
	}
	return AnalyzePackets(pkts, nil), nil
}

func uint32Bytes(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func uint16Bytes(v uint16) []byte {
	return []byte{byte(v), byte(v >> 8)}
}

func MergeCapFiles(inputs []string, output string) error {
	var allPkts []*Packet
	for _, path := range inputs {
		pkts, err := LoadPackets(path)
		if err != nil {
			return fmt.Errorf("ano: merge load %s: %w", path, err)
		}
		allPkts = append(allPkts, pkts...)
	}
	return SavePackets(output, allPkts)
}

func SplitCapFile(input string, outputDir string, maxPerFile int) error {
	pkts, err := LoadPackets(input)
	if err != nil {
		return fmt.Errorf("ano: split load %s: %w", input, err)
	}

	os.MkdirAll(outputDir, 0755)

	base := filepath.Base(input)
	base = strings.TrimSuffix(base, ".cap")
	base = strings.TrimSuffix(base, ".pcap")
	base = strings.TrimSuffix(base, ".pcapng")
	ext := ".pcap"
	if strings.HasSuffix(strings.ToLower(input), ".cap") {
		ext = ".cap"
	}

	for i := 0; i < len(pkts); i += maxPerFile {
		end := i + maxPerFile
		if end > len(pkts) {
			end = len(pkts)
		}
		chunk := pkts[i:end]
		name := filepath.Join(outputDir, fmt.Sprintf("%s_%d%s", base, i/maxPerFile+1, ext))
		if err := SavePackets(name, chunk); err != nil {
			return err
		}
	}

	return nil
}

func FileFormat(path string) string {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".cap") {
		return "cap"
	}
	if strings.HasSuffix(lower, ".pcapng") {
		return "pcapng"
	}
	return "pcap"
}