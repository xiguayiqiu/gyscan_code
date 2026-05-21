package wifie

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type CrackDevice int

const (
	CrackDeviceAuto CrackDevice = iota
	CrackDeviceCPU
	CrackDeviceGPU
	CrackDeviceOpenCL
)

func (d CrackDevice) String() string {
	switch d {
	case CrackDeviceAuto:
		return "auto"
	case CrackDeviceCPU:
		return "cpu"
	case CrackDeviceGPU:
		return "gpu"
	case CrackDeviceOpenCL:
		return "opencl"
	}
	return "unknown"
}

type CrackTarget struct {
	BSSID    string
	ESSID    string
	STAMAC   string
	ANonce   []byte
	SNonce   []byte
	EAPOL    []byte
	EAPOLSize int
	MIC      []byte
	KeyVer   uint8
	PMKID    []byte
}

type CrackConfig struct {
	Wordlist  string
	Targets   []CrackTarget
	Workers   int
	Device    CrackDevice
	ESSID     string
	Timeout   time.Duration
	Quiet     bool
	SessionFile string
	BSSIDFilter string
	StatusInterval time.Duration
}

type CrackResult struct {
	BSSID      string
	ESSID      string
	STAMAC     string
	Passphrase string
	PMK        [32]byte
	PTK        []byte
	MIC        []byte
	Method     string
	Elapsed    time.Duration
	Tried      uint64
	Speed      float64
	FoundAt    time.Time
}

type CrackSession struct {
	config    CrackConfig
	results   []CrackResult
	mu        sync.Mutex
	tried     uint64
	startTime time.Time
	stopCh    chan struct{}
	doneCh    chan struct{}
	found     int32
}

type CrackStats struct {
	Elapsed   time.Duration
	Tried     uint64
	Speed     float64
	Found     int
	Remaining int64
}

func (s *CrackSession) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

func (s *CrackSession) Wait() error {
	<-s.doneCh
	return nil
}

func (s *CrackSession) Results() []CrackResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := make([]CrackResult, len(s.results))
	copy(r, s.results)
	return r
}

func (s *CrackSession) Stats() CrackStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	elapsed := time.Since(s.startTime)
	tried := atomic.LoadUint64(&s.tried)
	speed := float64(0)
	if elapsed.Seconds() > 0 {
		speed = float64(tried) / elapsed.Seconds()
	}

	return CrackStats{
		Elapsed: elapsed,
		Tried:   tried,
		Speed:   speed,
		Found:   int(atomic.LoadInt32(&s.found)),
	}
}

func StartCrack(cfg CrackConfig) (*CrackSession, error) {
	if cfg.Wordlist == "" {
		return nil, fmt.Errorf("wifie: wordlist file is required")
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("wifie: at least one target is required")
	}
	for i := range cfg.Targets {
		if cfg.Targets[i].ESSID == "" && cfg.ESSID != "" {
			cfg.Targets[i].ESSID = cfg.ESSID
		}
	}

	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.StatusInterval <= 0 {
		cfg.StatusInterval = 3 * time.Second
	}

	if cfg.Device == CrackDeviceGPU || cfg.Device == CrackDeviceAuto {
		session, err := startGPUCrack(cfg)
		if err == nil && session != nil {
			return session, nil
		}
		if cfg.Device == CrackDeviceGPU {
			return nil, err
		}
	}

	session := &CrackSession{
		config:    cfg,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		startTime: time.Now(),
	}

	go session.run()

	return session, nil
}

func (s *CrackSession) run() {
	defer close(s.doneCh)

	passCh := make(chan string, s.config.Workers*16)
	var wg sync.WaitGroup

	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go s.worker(i, passCh, &wg)
	}

	s.readWordlist(passCh)

	close(passCh)
	wg.Wait()
}

func (s *CrackSession) readWordlist(passCh chan<- string) {
	defer func() {
		select {
		case <-s.stopCh:
		default:
			close(s.stopCh)
		}
	}()

	f, err := os.Open(s.config.Wordlist)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-s.stopCh:
			return
		default:
		}

		pass := strings.TrimSpace(scanner.Text())
		if len(pass) < 8 || len(pass) > 63 {
			continue
		}

		select {
		case passCh <- pass:
		case <-s.stopCh:
			return
		}
	}
}

type crackTargetData struct {
	bssid     string
	essid     []byte
	stamac    string
	anonce    []byte
	snonce    []byte
	pkeData   []byte
	eapolData []byte
	eapolSize int
	mic       []byte
	keyVer    uint8
	pmkid     []byte
}

func (s *CrackSession) worker(id int, passCh <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	td := s.buildTargetData()

	batch := make([]string, 0, 64)

	for {
		select {
		case <-s.stopCh:
			s.processBatchFast(batch, td)
			return
		case pass, ok := <-passCh:
			if !ok {
				s.processBatchFast(batch, td)
				return
			}
			batch = append(batch, pass)
			if len(batch) >= 64 {
				s.processBatchFast(batch, td)
				batch = batch[:0]
			}
		}
	}
}

func (s *CrackSession) buildTargetData() []crackTargetData {
	s.mu.Lock()
	targets := s.config.Targets
	s.mu.Unlock()

	td := make([]crackTargetData, len(targets))
	for i := range targets {
		t := &targets[i]
		td[i].bssid = t.BSSID
		td[i].essid = []byte(t.ESSID)
		td[i].stamac = t.STAMAC
		td[i].anonce = t.ANonce[:]
		td[i].snonce = t.SNonce[:]
		td[i].pkeData = PreComputePTKData(t.BSSID, t.STAMAC, t.ANonce[:], t.SNonce[:])
		td[i].eapolData = t.EAPOL
		td[i].eapolSize = t.EAPOLSize
		td[i].mic = t.MIC
		td[i].keyVer = t.KeyVer
		td[i].pmkid = t.PMKID
	}
	return td
}

func (s *CrackSession) processBatchFast(batch []string, td []crackTargetData) {
	if len(batch) == 0 {
		return
	}

	for _, pass := range batch {
		select {
		case <-s.stopCh:
			return
		default:
		}

		passBytes := []byte(pass)

		for ti := range td {
			t := &td[ti]

			if atomic.LoadInt32(&s.found) > 0 && len(td) == 1 {
				return
			}

			var found bool
			if t.eapolSize > 0 && len(t.mic) > 0 {
				pmk := CalcPMK(passBytes, t.essid)
				ptk := CalcPTKWithData(pmk[:], t.pkeData, t.keyVer)
				mic, err := CalcEAPOLMIC(t.eapolData[:t.eapolSize], ptk, t.keyVer)
				if err == nil {
					found = true
					for j := 0; j < 16 && j < len(mic) && j < len(t.mic); j++ {
						if mic[j] != t.mic[j] {
							found = false
							break
						}
					}
				}
			} else if len(t.pmkid) > 0 {
				pmk := CalcPMK(passBytes, t.essid)
				calc := CalcPMKID(pmk[:], t.bssid, t.stamac)
				found = true
				for j := 0; j < 16 && j < len(calc) && j < len(t.pmkid); j++ {
					if calc[j] != t.pmkid[j] {
						found = false
						break
					}
				}
			}

			if found {
				result := CrackResult{
					BSSID:      t.bssid,
					ESSID:      string(t.essid),
					STAMAC:     t.stamac,
					Passphrase: pass,
					FoundAt:    time.Now(),
					Elapsed:    time.Since(s.startTime),
					Tried:      atomic.LoadUint64(&s.tried),
					Method:     "handshake",
				}
				pmk := CalcPMK(passBytes, t.essid)
				copy(result.PMK[:], pmk[:])
				result.PTK = CalcPTKWithData(pmk[:], t.pkeData, t.keyVer)
				result.MIC = t.mic

				s.mu.Lock()
				s.results = append(s.results, result)
				s.mu.Unlock()
				atomic.AddInt32(&s.found, 1)

				if len(td) == 1 {
					s.Stop()
				}
			}
		}

		atomic.AddUint64(&s.tried, 1)
	}
}

func tryCrackTarget(pass []byte, t *CrackTarget) bool {
	if t.EAPOLSize > 0 && len(t.EAPOL) > 0 && len(t.MIC) > 0 {
		return TryWPAKey(pass, []byte(t.ESSID), t.BSSID, t.STAMAC, t.ANonce, t.SNonce, t.EAPOL, t.EAPOLSize, t.MIC, t.KeyVer)
	}

	if len(t.PMKID) > 0 {
		pmk := CalcPMK(pass, []byte(t.ESSID))
		return TryPMKID(pmk[:], t.PMKID, t.BSSID, t.STAMAC)
	}

	return false
}

func CrackHandshake(cfg CrackConfig, callback func(CrackStats), resultCallback func(CrackResult)) ([]CrackResult, error) {
	session, err := StartCrack(cfg)
	if err != nil {
		return nil, err
	}

	ticker := time.NewTicker(cfg.StatusInterval)
	defer ticker.Stop()

	doneCh := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				if callback != nil {
					callback(session.Stats())
				}
			case <-doneCh:
				return
			}
		}
	}()

	session.Wait()
	close(doneCh)

	results := session.Results()

	for _, r := range results {
		if resultCallback != nil {
			resultCallback(r)
		}
	}

	return results, nil
}

func LoadTargetsFromCap(capFile string, essid string) ([]CrackTarget, error) {
	data, err := os.ReadFile(capFile)
	if err != nil {
		return nil, fmt.Errorf("wifie: read cap file: %w", err)
	}

	if essid == "" {
		essid = "unknown"
	}

	handshakes := make(map[string]*WPAHandshake)

	_ = ParsePcapFile(data, LINKTYPE_IEEE802_11_RADIOTAP, func(frame *Frame80211, ts time.Time) error {
		if !IsEAPOLFrame(frame) {
			return nil
		}

		bssid := GetBSSID(frame)
		if bssid == "" {
			return nil
		}

		hs, ok := handshakes[bssid]
		if !ok {
			hs = &WPAHandshake{}
			handshakes[bssid] = hs
		}

		DetectWPAHandshake(frame, hs)
		return nil
	})

	targets := make([]CrackTarget, 0, len(handshakes))
	for bssid, hs := range handshakes {
		if !hs.Complete {
			continue
		}

		anonce := make([]byte, 32)
		snonce := make([]byte, 32)
		copy(anonce, hs.ANonce[:])
		copy(snonce, hs.SNonce[:])

		target := CrackTarget{
			BSSID:   bssid,
			ESSID:   essid,
			STAMAC:  hs.STAMAC,
			KeyVer:  hs.Version,
			ANonce:  anonce,
			SNonce:  snonce,
		}

		if len(hs.MIC) > 0 {
			target.MIC = make([]byte, len(hs.MIC))
			copy(target.MIC, hs.MIC[:])
		}

		if hs.EAPOLSize > 0 && hs.EAPOLSize <= 256 {
			target.EAPOL = make([]byte, hs.EAPOLSize)
			copy(target.EAPOL, hs.EAPOLData[:hs.EAPOLSize])
			target.EAPOLSize = hs.EAPOLSize
		}

		if len(hs.PMKID) > 0 {
			target.PMKID = make([]byte, len(hs.PMKID))
			copy(target.PMKID, hs.PMKID)
		}

		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("wifie: no complete WPA handshakes found in cap file")
	}

	return targets, nil
}

func (s *CrackSession) SaveSession(filename string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, "# Wifie Crack Session\n")
	fmt.Fprintf(f, "wordlist=%s\n", s.config.Wordlist)
	fmt.Fprintf(f, "tried=%d\n", atomic.LoadUint64(&s.tried))
	fmt.Fprintf(f, "workers=%d\n", s.config.Workers)
	fmt.Fprintf(f, "elapsed=%s\n", time.Since(s.startTime))
	fmt.Fprintf(f, "found=%d\n", atomic.LoadInt32(&s.found))

	return nil
}

func (s *CrackSession) Found() bool {
	return atomic.LoadInt32(&s.found) > 0
}

func (s *CrackSession) Tried() uint64 {
	return atomic.LoadUint64(&s.tried)
}