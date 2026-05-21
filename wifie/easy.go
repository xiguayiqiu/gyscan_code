package wifie

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type Wifie struct {
	iface      string
	timeout    time.Duration
	verbose    bool
	ctx        context.Context
}

func New() *Wifie {
	return &Wifie{
		timeout: 30 * time.Second,
		ctx:     context.Background(),
	}
}

func (w *Wifie) Interface(name string) *Wifie {
	w.iface = name
	return w
}

func (w *Wifie) Timeout(d time.Duration) *Wifie {
	w.timeout = d
	return w
}

func (w *Wifie) Verbose(v bool) *Wifie {
	w.verbose = v
	return w
}

func (w *Wifie) Context(ctx context.Context) *Wifie {
	w.ctx = ctx
	return w
}

func (w *Wifie) Scan() (*ScanResult, error) {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return nil, err
		}
		w.iface = nic.Name
	}

	networks, err := QuickScan(w.iface, w.timeout)
	if err != nil {
		return nil, err
	}

	return &ScanResult{
		Networks: networks,
		Duration: w.timeout.Seconds(),
	}, nil
}

func (w *Wifie) FullScan(channels []int, callback func(*WiFiNetwork)) error {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return err
		}
		w.iface = nic.Name
	}

	monIface, err := EnableMonitorMode(w.iface)
	if err != nil {
		return err
	}
	defer DisableMonitorMode(monIface)

	SetChannel(monIface, 1)

	return LiveScan(monIface, w.timeout, channels, callback)
}

func (w *Wifie) Deauth(bssid, client string, count int) (*DeauthResult, error) {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return nil, err
		}
		w.iface = nic.Name
	}

	return SendDeauth(w.iface, bssid, client, count)
}

func (w *Wifie) SecurityAudit() *AuditReport {
	report := &AuditReport{
		Time:     time.Now(),
		Findings: make([]AuditFinding, 0),
		RiskLevel: "NONE",
	}

	scanResult, err := w.Scan()
	if err != nil {
		report.Findings = append(report.Findings, AuditFinding{
			Severity: "ERROR",
			Category: "Scanner",
			Title:    "Scan Failed",
			Detail:   err.Error(),
		})
		return report
	}

	for _, net := range scanResult.Networks {
		si := AnalyzeSecurity(net)

		switch si.RiskLevel() {
		case "CRITICAL":
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "CRITICAL",
				Category: "Encryption",
				Title:    fmt.Sprintf("%s Network (%s)", si.Standard, net.ESSID),
				Device:   net.BSSID,
				Detail:   fmt.Sprintf("Channel %d, Signal %d dBm - %s encryption is insecure",
					net.Channel, net.Signal, si.Standard),
			})
		case "HIGH":
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "HIGH",
				Category: "Encryption",
				Title:    fmt.Sprintf("%s with TKIP (%s)", si.Standard, net.ESSID),
				Device:   net.BSSID,
				Detail:   fmt.Sprintf("Channel %d - TKIP cipher is deprecated and vulnerable", net.Channel),
			})
		case "MEDIUM":
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "MEDIUM",
				Category: "Encryption",
				Title:    fmt.Sprintf("PMKID Available (%s)", net.ESSID),
				Device:   net.BSSID,
				Detail:   "PMKID is available for roaming attack",
			})
		case "LOW":
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "LOW",
				Category: "Encryption",
				Title:    fmt.Sprintf("WPA Network (%s)", net.ESSID),
				Device:   net.BSSID,
				Detail:   "WPA (TKIP) has known vulnerabilities, upgrade to WPA2/WPA3",
			})
		case "NONE":
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "INFO",
				Category: "Encryption",
				Title:    fmt.Sprintf("Secure Network: %s (%s)", si.Standard, net.ESSID),
				Device:   net.BSSID,
				Detail:   fmt.Sprintf("Channel %d, Cipher %s, Auth %s",
					net.Channel, si.Cipher, si.Auth),
			})
		}

		if CheckWPS(net) {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "HIGH",
				Category: "Configuration",
				Title:    fmt.Sprintf("WPS Enabled (%s)", net.ESSID),
				Device:   net.BSSID,
				Detail:   "WPS is enabled and susceptible to brute-force attacks",
			})
		}
	}

	report.TotalNetworks = len(scanResult.Networks)
	report.TotalFindings = len(report.Findings)
	report.calcRiskLevel()

	return report
}

func (w *Wifie) GetInterface() (*WiFiInterface, error) {
	if w.iface == "" {
		return DefaultWiFiInterface()
	}
	return GetInterface(w.iface)
}

func (w *Wifie) ListInterfaces() ([]WiFiInterface, error) {
	return ListInterfaces()
}

func (w *Wifie) SetChannel(channel int) error {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return err
		}
		w.iface = nic.Name
	}
	return SetChannel(w.iface, channel)
}

func (w *Wifie) IsMonitor() bool {
	if w.iface == "" {
		return false
	}
	return IsMonitorMode(w.iface)
}

func (w *Wifie) WPAHandshakeCapture(bssid string, channel int) (*WPAHandshake, error) {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return nil, err
		}
		w.iface = nic.Name
	}

	cfg := CaptureConfig{
		Iface:   w.iface,
		BSSID:   bssid,
		Channel: channel,
		Timeout: w.timeout,
	}
	return ListenForHandshake(cfg)
}

func (w *Wifie) PcapAnalysis(filename string) (*ScanResult, []*WPAHandshake, error) {
	networks := make(map[string]*WiFiNetwork)
	handshakes := make([]*WPAHandshake, 0)

	err := ScanPcapFile(filename, func(net *WiFiNetwork, hs *WPAHandshake) {
		if net != nil {
			networks[net.BSSID] = net
		}
		if hs != nil {
			handshakes = append(handshakes, hs)
		}
	})

	netList := make([]*WiFiNetwork, 0, len(networks))
	for _, net := range networks {
		netList = append(netList, net)
	}

	sort.Slice(netList, func(i, j int) bool {
		return netList[i].Signal > netList[j].Signal
	})

	scan := &ScanResult{
		Networks: netList,
	}

	return scan, handshakes, err
}

func (w *Wifie) Inject(packet []byte) error {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return err
		}
		w.iface = nic.Name
	}
	return InjectPacket(w.iface, packet)
}

func (w *Wifie) Probe(bssid string) error {
	if w.iface == "" {
		nic, err := DefaultWiFiInterface()
		if err != nil {
			return err
		}
		w.iface = nic.Name
	}
	return SendProbeRequest(w.iface, bssid)
}

func (w *Wifie) Channel(channel int) *Wifie {
	if w.iface != "" {
		SetChannel(w.iface, channel)
	}
	return w
}

func (w *Wifie) ChannelsChan() []int {
	if w.iface == "" {
		return SupportedChannels24GHz()
	}
	ch, _ := GetSupportedChannels(w.iface)
	return ch
}

func PcapScan(filename string) (*ScanResult, []*WPAHandshake, error) {
	return New().PcapAnalysis(filename)
}

func CrackWPA(hs *WPAHandshake, passphrases [][]byte, essid []byte) ([]byte, bool) {
	for _, pw := range passphrases {
		if TryWPAKey(pw, essid, hs.BSSID, hs.STAMAC, hs.ANonce[:], hs.SNonce[:], hs.EAPOLData[:hs.EAPOLSize], hs.EAPOLSize, hs.MIC[:], hs.Version) {
			return pw, true
		}
	}
	return nil, false
}

func CrackPMKID(pmkid []byte, bssid, stamac string, passphrases [][]byte, essid []byte) ([]byte, bool) {
	for _, pw := range passphrases {
		pmk := CalcPMK(pw, essid)
		if TryPMKID(pmk[:], pmkid, bssid, stamac) {
			return pw, true
		}
	}
	return nil, false
}

func DecryptWEP(packets [][]byte, key []byte) ([][]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("wifie: empty WEP key")
	}

	decrypted := make([][]byte, len(packets))
	for i, pkt := range packets {
		data, err := WEPDecrypt(key, pkt)
		if err != nil {
			return nil, err
		}
		decrypted[i] = data
	}
	return decrypted, nil
}

func QuickScan(iface string, timeout time.Duration) ([]*WiFiNetwork, error) {
	if IsMonitorMode(iface) {
		networks := make([]*WiFiNetwork, 0)
		seen := make(map[string]bool)
		err := LiveScan(iface, timeout, nil, func(net *WiFiNetwork) {
			if !seen[net.BSSID] {
				seen[net.BSSID] = true
				networks = append(networks, net)
			}
		})
		sort.Slice(networks, func(i, j int) bool {
			return networks[i].Signal > networks[j].Signal
		})
		return networks, err
	}

	networks := make([]*WiFiNetwork, 0)
	seen := make(map[string]bool)
	err := liveScanManaged(iface, timeout, func(net *WiFiNetwork) {
		if !seen[net.BSSID] {
			seen[net.BSSID] = true
			networks = append(networks, net)
		}
	})
	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Signal > networks[j].Signal
	})
	return networks, err
}

type AuditFinding struct {
	Severity string
	Category string
	Title    string
	Device   string
	Detail   string
}

type AuditReport struct {
	Time          time.Time
	RiskLevel     string
	TotalNetworks int
	TotalFindings int
	Findings      []AuditFinding
}

func (r *AuditReport) calcRiskLevel() {
	riskCounts := map[string]int{}
	for _, f := range r.Findings {
		riskCounts[f.Severity]++
	}

	if riskCounts["CRITICAL"] > 0 {
		r.RiskLevel = "CRITICAL"
	} else if riskCounts["HIGH"] > 0 {
		r.RiskLevel = "HIGH"
	} else if riskCounts["MEDIUM"] > 0 {
		r.RiskLevel = "MEDIUM"
	} else if riskCounts["LOW"] > 0 {
		r.RiskLevel = "LOW"
	} else {
		r.RiskLevel = "INFO"
	}
}

func (r *AuditReport) String() string {
	s := fmt.Sprintf("=== WiFi Security Audit Report ===\n")
	s += fmt.Sprintf("Time: %s\n", r.Time.Format(time.RFC3339))
	s += fmt.Sprintf("Networks Found: %d\n", r.TotalNetworks)
	s += fmt.Sprintf("Total Findings: %d\n", r.TotalFindings)
	s += fmt.Sprintf("Overall Risk Level: %s\n", r.RiskLevel)
	s += fmt.Sprintf("\n--- Findings ---\n")

	sortFindings(r.Findings)
	for i, f := range r.Findings {
		s += fmt.Sprintf("[%d] [%s] %s: %s\n     Device: %s\n     %s\n",
			i+1, f.Severity, f.Category, f.Title, f.Device, f.Detail)
	}

	return s
}

func sortFindings(findings []AuditFinding) {
	order := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"INFO":     4,
		"ERROR":    5,
	}

	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] < order[findings[j].Severity]
	})
}

func Scan() *AuditReport {
	return New().SecurityAudit()
}

func Audit() *AuditReport {
	return New().SecurityAudit()
}

func StartScan(iface string) *Wifie {
	return New().Interface(iface)
}