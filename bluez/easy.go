package bluez

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type BlueZ struct {
	config      *AttackConfig
	sniffer     *SnifferConfig
	blueConfig  *BluejackingConfig
	bleConfig   *BLEConfig
	physical    *PhysicalLayer
	link        *LinkLayer
	host        *HostLayer
	social      *SocialLayer
	ble         *BLELayer
	verbose     bool
	ctx         context.Context
}

func New() *BlueZ {
	cfg := DefaultAttackConfig()
	return &BlueZ{
		config:     cfg,
		sniffer:    DefaultSnifferConfig(),
		blueConfig: DefaultBluejackingConfig(),
		bleConfig:  DefaultBLEConfig(),
		physical:   NewPhysicalLayer().Config(cfg),
		link:       NewLinkLayer().Config(cfg),
		host:       NewHostLayer().Config(cfg),
		social:     NewSocialLayer().Config(cfg),
		ble:        NewBLELayer(),
		ctx:        context.Background(),
	}
}

func (b *BlueZ) Context(ctx context.Context) *BlueZ {
	b.ctx = ctx
	return b
}

func (b *BlueZ) Target(addr string) *BlueZ {
	parsed, err := ParseBDAddr(addr)
	if err == nil {
		b.config.Target = parsed
		b.physical.Config(b.config)
		b.link.Config(b.config)
		b.host.Config(b.config)
		b.social.Config(b.config)
	}
	return b
}

func (b *BlueZ) Timeout(d time.Duration) *BlueZ {
	b.config.Timeout = d
	b.bleConfig.ScanTimeout = d
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	return b
}

func (b *BlueZ) Verbose(v bool) *BlueZ {
	b.verbose = v
	b.config.Verbose = v
	b.sniffer.Verbose = v
	b.blueConfig.Verbose = v
	b.bleConfig.Verbose = v
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	b.ble.Config(b.bleConfig)
	return b
}

func (b *BlueZ) PinCode(pin string) *BlueZ {
	b.config.PinCode = pin
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	return b
}

func (b *BlueZ) KeySize(size uint8) *BlueZ {
	b.config.KeySize = size
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	return b
}

func (b *BlueZ) IOCap(cap uint8) *BlueZ {
	b.config.IOCap = cap
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	return b
}

func (b *BlueZ) EncryptSize(size uint8) *BlueZ {
	b.config.EncryptSize = size
	b.physical.Config(b.config)
	b.link.Config(b.config)
	b.host.Config(b.config)
	b.social.Config(b.config)
	return b
}

func (b *BlueZ) BLEScanTimeout(d time.Duration) *BlueZ {
	b.bleConfig.ScanTimeout = d
	b.ble.Config(b.bleConfig)
	return b
}

func (b *BlueZ) BLEScanActive(active bool) *BlueZ {
	b.bleConfig.ActiveScan = active
	if active {
		b.bleConfig.ScanType = BLE_SCAN_ACTIVE
	} else {
		b.bleConfig.ScanType = BLE_SCAN_PASSIVE
	}
	b.ble.Config(b.bleConfig)
	return b
}

func (b *BlueZ) Sniff(timeout time.Duration) []PacketRecord {
	b.sniffer.Timeout = timeout
	b.physical.Sniffer(b.sniffer)
	return b.physical.RFSniffSafe()
}

func (b *BlueZ) SniffWithContext(timeout time.Duration) []PacketRecord {
	b.sniffer.Timeout = timeout
	b.physical.Sniffer(b.sniffer)
	records, _ := b.physical.RFSniffWithContext(context.Background())
	return records
}

func (b *BlueZ) Track(duration time.Duration) []TrackRecord {
	records, _ := b.physical.TrackDevice(duration)
	result := make([]TrackRecord, 0, len(records))
	for _, r := range records {
		result = append(result, TrackRecord{
			Address:  r.Address,
			RSSI:     r.RSSI,
			Time:     r.Time,
			Location: r.Location,
		})
	}
	return result
}

func (b *BlueZ) DoS(floodType string) error {
	if err := checkRedTeam("DoSFlood"); err != nil {
		return err
	}
	auditOperation("DoSFlood", b.config.Target.SafeString(b.verbose), false,
		fmt.Sprintf("type=%s timeout=%v", floodType, b.config.Timeout))

	err := b.physical.DoSFlood(floodType)
	auditOperation("DoSFlood", b.config.Target.SafeString(b.verbose), err == nil,
		fmt.Sprintf("completed with error=%v", err))
	return err
}

func (b *BlueZ) KNOB() *KNOBResult {
	if err := checkRedTeam("KNOBAttack"); err != nil {
		return &KNOBResult{Details: err.Error()}
	}
	auditOperation("KNOBAttack", b.config.Target.SafeString(b.verbose), false,
		fmt.Sprintf("keySize=%d", b.config.KeySize))

	result, _ := b.link.KNOBAttack()
	auditOperation("KNOBAttack", b.config.Target.SafeString(b.verbose), result.Success,
		result.Details)
	return result
}

func (b *BlueZ) BIAS() *BIASResult {
	if err := checkRedTeam("BIASAttack"); err != nil {
		return &BIASResult{Details: err.Error()}
	}
	auditOperation("BIASAttack", b.config.Target.SafeString(b.verbose), false,
		"attempting BIAS")
	result, _ := b.link.BIASAttack()
	auditOperation("BIASAttack", b.config.Target.SafeString(b.verbose), result.Success,
		result.Details)
	return result
}

func (b *BlueZ) MITM() *MITMResult {
	if err := checkRedTeam("MITMAttack"); err != nil {
		return &MITMResult{Details: err.Error()}
	}
	auditOperation("MITMAttack", b.config.Target.SafeString(b.verbose), false,
		"attempting MITM")
	result, _ := b.link.MITMAttack()
	auditOperation("MITMAttack", b.config.Target.SafeString(b.verbose), result.Success,
		result.Details)
	return result
}

func (b *BlueZ) Replay(data []byte) *ReplayResult {
	if err := checkRedTeam("ReplayAttack"); err != nil {
		return &ReplayResult{Details: err.Error()}
	}
	auditOperation("ReplayAttack", b.config.Target.SafeString(b.verbose), false,
		fmt.Sprintf("dataLen=%d", len(data)))
	result, _ := b.link.ReplayAttack(data)
	auditOperation("ReplayAttack", b.config.Target.SafeString(b.verbose), result.Success,
		result.Details)
	return result
}

func (b *BlueZ) BlueBorne() *BlueBorneResult {
	if err := checkRedTeam("BlueBorne"); err != nil {
		return &BlueBorneResult{Details: err.Error()}
	}
	auditOperation("BlueBorne", b.config.Target.SafeString(b.verbose), false,
		"scanning for BlueBorne vulnerabilities")
	result, _ := b.host.BlueBorne()
	auditOperation("BlueBorne", b.config.Target.SafeString(b.verbose), result.Vulnerable,
		result.Details)
	return result
}

func (b *BlueZ) Bluesnarfing() *BluesnarfingResult {
	if err := checkRedTeam("Bluesnarfing"); err != nil {
		return &BluesnarfingResult{Details: err.Error()}
	}
	auditOperation("Bluesnarfing", b.config.Target.SafeString(b.verbose), false,
		"attempting OBEX file extraction")
	result, _ := b.host.Bluesnarfing()
	auditOperation("Bluesnarfing", b.config.Target.SafeString(b.verbose), result.Success,
		fmt.Sprintf("extracted %d files", len(result.Extracted)))
	return result
}

func (b *BlueZ) Bluebugging() *BluebuggingResult {
	if err := checkRedTeam("Bluebugging"); err != nil {
		return &BluebuggingResult{Details: err.Error()}
	}
	auditOperation("Bluebugging", b.config.Target.SafeString(b.verbose), false,
		"attempting AT command control")
	result, _ := b.host.Bluebugging()
	auditOperation("Bluebugging", b.config.Target.SafeString(b.verbose), result.Success,
		fmt.Sprintf("control=%v commands=%d", result.ControlGained, len(result.CommandsSent)))
	return result
}

func (b *BlueZ) Firmware() *FirmwareResult {
	if err := checkRedTeam("FirmwareTamper"); err != nil {
		return &FirmwareResult{Details: err.Error()}
	}
	auditOperation("FirmwareTamper", b.config.Target.SafeString(b.verbose), false,
		"probing firmware")
	result, _ := b.host.FirmwareTamper()
	auditOperation("FirmwareTamper", b.config.Target.SafeString(b.verbose), result.Success,
		result.Details)
	return result
}

func (b *BlueZ) Bluejack(msg string) *BluejackingResult {
	if err := checkRedTeam("Bluejacking"); err != nil {
		return &BluejackingResult{Details: err.Error()}
	}
	b.blueConfig.Message = msg
	b.social.Bluejack(b.blueConfig)
	auditOperation("Bluejacking", "broadcast", false,
		fmt.Sprintf("message='%s'", msg[:min(20, len(msg))]))
	result, _ := b.social.Bluejacking()
	auditOperation("Bluejacking", "broadcast", result.Success,
		fmt.Sprintf("sent to %d devices", result.DevicesSent))
	return result
}

func (b *BlueZ) WeakPIN() []WPScanResult {
	if err := checkRedTeam("WeakPINBrute"); err != nil {
		return []WPScanResult{{Details: err.Error()}}
	}
	auditOperation("WeakPINBrute", "broadcast", false, "attempting weak PIN brute force")
	results, _ := b.social.WeakPINBrute()
	auditOperation("WeakPINBrute", "broadcast", len(results) > 0,
		fmt.Sprintf("found %d vulnerable devices", len(results)))
	return results
}

func (b *BlueZ) Discoverable() []DiscoverableDevice {
	devices, _ := b.social.DiscoverableScan()
	return devices
}

func (b *BlueZ) Scan() *ScanResult {
	start := time.Now()
	devices, _ := b.social.discoverDevices(8 * time.Second)
	discoverable, _ := b.social.DiscoverableScan()
	bleDevices, _ := b.ble.Scan(b.ctx)

	return &ScanResult{
		Devices:      devices,
		Discoverable: discoverable,
		BLEDevices:   bleDevices,
		Duration:     time.Since(start),
	}
}

func (b *BlueZ) BLEScan() ([]BLEDevice, error) {
	return b.ble.Scan(b.ctx)
}

func (b *BlueZ) BLEDiscoverGATT(target string) ([]GATTService, error) {
	addr, err := ParseBDAddr(target)
	if err != nil {
		return nil, err
	}
	return b.ble.DiscoverGATT(b.ctx, addr)
}

func (b *BlueZ) BLEPairingAttack(target string, method string) (*BLEPairingResult, error) {
	addr, err := ParseBDAddr(target)
	if err != nil {
		return &BLEPairingResult{Details: err.Error()}, err
	}
	return b.ble.PairingAttack(b.ctx, addr, method)
}

func (b *BlueZ) SecurityAudit() *AuditReport {
	report := &AuditReport{
		Time:        time.Now(),
		Findings:    make([]AuditFinding, 0),
		RiskLevel:   "NONE",
	}

	devices := b.Scan()

	report.TotalDevices = len(devices.Devices) + len(devices.Discoverable) + len(devices.BLEDevices)

	for _, d := range devices.Discoverable {
		if d.Class&CLASS_SERVICE_OBJECT_TRANSFER != 0 {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "HIGH",
				Category: "Host Layer",
				Title:    "OBEX Service Exposed",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   "File transfer service is exposed, susceptible to Bluesnarfing attacks",
			})
		}
		if d.Class&CLASS_SERVICE_TELEPHONY != 0 {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "CRITICAL",
				Category: "Host Layer",
				Title:    "Telephony Service Exposed",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   "Telephony service exposed - susceptible to Bluebugging attacks",
			})
		}
		if d.Class&CLASS_SERVICE_NETWORKING != 0 {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "MEDIUM",
				Category: "Host Layer",
				Title:    "Network Service Exposed",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   "Network service exposed - potential BlueBorne attack surface",
			})
		}
		if d.RSSI >= -55 {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "LOW",
				Category: "Physical Layer",
				Title:    "Strong Proximity Signal",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   fmt.Sprintf("Device at close range (RSSI: %d dBm) - physical tracking risk", d.RSSI),
			})
		}
		if d.Name == "" || containsDefault(d.Name) {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "LOW",
				Category: "Social Layer",
				Title:    "Default/No Device Name",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   "Device name not set or uses default - information leakage",
			})
		}
	}

	for _, d := range devices.Devices {
		report.Findings = append(report.Findings, AuditFinding{
			Severity: "INFO",
			Category: "Configuration",
			Title:    "Device in Discoverable Mode",
			Device:   d.Address.SafeString(b.verbose),
			Detail:   fmt.Sprintf("Device %s is discoverable (RSSI: %d dBm, Class: %s)",
				d.Address.SafeString(b.verbose), d.RSSI, ClassToString(d.Class)),
		})
	}

	for _, d := range devices.BLEDevices {
		report.Findings = append(report.Findings, AuditFinding{
			Severity: "INFO",
			Category: "BLE",
			Title:    "BLE Device in Range",
			Device:   d.Address.SafeString(b.verbose),
			Detail:   fmt.Sprintf("BLE device %s (Name: %s, RSSI: %d dBm, Services: %d)",
				d.Address.SafeString(b.verbose), d.Name, d.RSSI, len(d.Services)),
		})
		if d.Name == "" {
			report.Findings = append(report.Findings, AuditFinding{
				Severity: "LOW",
				Category: "BLE",
				Title:    "Anonymous BLE Device",
				Device:   d.Address.SafeString(b.verbose),
				Detail:   "BLE device without name broadcast - may indicate privacy concern or tracking device",
			})
		}
	}

	riskCounts := map[string]int{}
	for _, f := range report.Findings {
		riskCounts[f.Severity]++
	}

	if riskCounts["CRITICAL"] > 0 {
		report.RiskLevel = "CRITICAL"
	} else if riskCounts["HIGH"] > 0 {
		report.RiskLevel = "HIGH"
	} else if riskCounts["MEDIUM"] > 0 {
		report.RiskLevel = "MEDIUM"
	} else if riskCounts["LOW"] > 0 {
		report.RiskLevel = "LOW"
	}

	sortFindings(report.Findings)
	report.TotalFindings = len(report.Findings)

	auditOperation("SecurityAudit", "environment", true,
		fmt.Sprintf("risk=%s devices=%d findings=%d", report.RiskLevel, report.TotalDevices, report.TotalFindings))

	return report
}

func (r *AuditReport) String() string {
	s := fmt.Sprintf("=== Bluetooth Security Audit Report ===\n")
	s += fmt.Sprintf("Time: %s\n", r.Time.Format(time.RFC3339))
	s += fmt.Sprintf("Devices Found: %d\n", r.TotalDevices)
	s += fmt.Sprintf("Total Findings: %d\n", r.TotalFindings)
	s += fmt.Sprintf("Overall Risk Level: %s\n", r.RiskLevel)
	s += fmt.Sprintf("\n--- Findings ---\n")

	for i, f := range r.Findings {
		s += fmt.Sprintf("[%d] [%s] %s: %s\n     Device: %s\n     %s\n",
			i+1, f.Severity, f.Category, f.Title, f.Device, f.Detail)
	}

	return s
}

func containsDefault(name string) bool {
	defaults := []string{"default", "unknown", "unnamed", "new device", "bluetooth"}
	lower := toLower(name)
	for _, d := range defaults {
		if containsStr(lower, d) {
			return true
		}
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func sortFindings(findings []AuditFinding) {
	order := map[string]int{
		"CRITICAL": 0,
		"HIGH":     1,
		"MEDIUM":   2,
		"LOW":      3,
		"INFO":     4,
	}

	sort.Slice(findings, func(i, j int) bool {
		return order[findings[i].Severity] < order[findings[j].Severity]
	})
}

func Scan() *ScanResult {
	return New().Scan()
}

func Audit() *AuditReport {
	return New().SecurityAudit()
}