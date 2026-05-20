package bluez

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

type EnforcementMode int

const (
	MODE_SAFE     EnforcementMode = iota
	MODE_RED_TEAM
)

const legalBypassEnv = "BLUEZ_BYPASS_LEGAL"
const legalBypassToken = "IAcceptFullLegalResponsibility"

type AuditEntry struct {
	Time       time.Time
	Operation  string
	TargetMAC  string
	CallerIP   string
	Success    bool
	Details    string
	Signature  string
}

type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	file    string
}

var (
	globalMode    EnforcementMode = MODE_SAFE
	globalAudit   *AuditLog
	modeMu        sync.Mutex
)

func init() {
	globalAudit = &AuditLog{
		entries: make([]AuditEntry, 0),
	}

	if os.Getenv(legalBypassEnv) == legalBypassToken {
		globalMode = MODE_RED_TEAM
	}
}

func GetMode() EnforcementMode {
	modeMu.Lock()
	defer modeMu.Unlock()
	return globalMode
}

func SetMode(mode EnforcementMode) {
	modeMu.Lock()
	defer modeMu.Unlock()
	globalMode = mode
}

func EnableRedTeam(token string) error {
	if token != legalBypassToken {
		return fmt.Errorf("invalid red team token: must be '%s'", legalBypassToken)
	}
	SetMode(MODE_RED_TEAM)
	return nil
}

func DisableRedTeam() {
	SetMode(MODE_SAFE)
}

func checkRedTeam(operation string) error {
	if GetMode() != MODE_RED_TEAM {
		return fmt.Errorf("BLUEZ_SAFE_MODE: operation '%s' is blocked in safe mode. "+
			"Set environment %s=%s or call EnableRedTeam() to unlock attack functions",
			operation, legalBypassEnv, legalBypassToken)
	}
	return nil
}

var safeOps = map[string]bool{
	"Scan":              true,
	"SecurityAudit":     true,
	"Audit":             true,
	"DiscoverableScan":  true,
	"AnalyzeRisk":       true,
	"RFSniff":           true,
	"TrackDevice":       true,
	"ClassToString":     true,
	"RSSIToDistance":    true,
}

func isSafeOperation(op string) bool {
	return safeOps[op]
}

func logAudit(entry AuditEntry) {
	entry.Signature = signAuditEntry(entry)
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	globalAudit.entries = append(globalAudit.entries, entry)
}

func signAuditEntry(e AuditEntry) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%t|%s",
		e.Time.Format(time.RFC3339Nano), e.Operation, e.TargetMAC, e.CallerIP, e.Success, e.Details)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func GetAuditLog() []AuditEntry {
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	result := make([]AuditEntry, len(globalAudit.entries))
	copy(result, globalAudit.entries)
	return result
}

func ClearAuditLog() {
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	globalAudit.entries = globalAudit.entries[:0]
}

func VerifyAuditIntegrity() bool {
	globalAudit.mu.Lock()
	defer globalAudit.mu.Unlock()
	for _, e := range globalAudit.entries {
		expected := signAuditEntry(e)
		if e.Signature != expected {
			return false
		}
	}
	return true
}

func auditOperation(operation, targetMAC string, success bool, details string) {
	logAudit(AuditEntry{
		Time:      time.Now(),
		Operation: operation,
		TargetMAC: targetMAC,
		CallerIP:  "localhost",
		Success:   success,
		Details:   details,
	})
}

func (a BDAddr) Anonymize() string {
	s := a.String()
	if len(s) < 8 {
		return "XX:XX:XX:XX:XX:XX"
	}
	return s[:8] + "...:" + s[len(s)-5:]
}

func (a BDAddr) SafeString(verbose bool) string {
	if verbose {
		return a.String()
	}
	return a.Anonymize()
}