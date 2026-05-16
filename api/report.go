package api

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ReportMetadata struct {
	GeneratedAt string   `json:"generated_at"`
	Version     string   `json:"version"`
	Target      string   `json:"target"`
	TotalAPIs   int      `json:"total_apis"`
	Sources     []string `json:"sources"`
	Mode        string   `json:"mode"`
}

type Report struct {
	Metadata  ReportMetadata `json:"metadata"`
	Endpoints []APIEndpoint  `json:"endpoints"`
	Stats     ReportStats    `json:"stats"`
}

type ReportStats struct {
	ByConfidence map[string]int `json:"by_confidence"`
	ByMethod     map[string]int `json:"by_method"`
	BySource     map[string]int `json:"by_source"`
	StaticFiltered int         `json:"static_filtered"`
	LowConfidence  int         `json:"low_confidence"`
}

func GenerateReport(target string, endpoints []APIEndpoint, mode DiscoveryMode) *Report {
	stats := computeStats(endpoints)

	return &Report{
		Metadata: ReportMetadata{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Version:     "1.0.0",
			Target:      target,
			TotalAPIs:   len(endpoints),
			Sources:     stats.sourceList(),
			Mode:        modeToString(mode),
		},
		Endpoints: endpoints,
		Stats:     stats,
	}
}

func computeStats(endpoints []APIEndpoint) ReportStats {
	stats := ReportStats{
		ByConfidence: make(map[string]int),
		ByMethod:     make(map[string]int),
		BySource:     make(map[string]int),
	}

	for _, ep := range endpoints {
		switch {
		case ep.Confidence >= 1.0:
			stats.ByConfidence["high"]++
		case ep.Confidence >= 0.7:
			stats.ByConfidence["medium"]++
		case ep.Confidence > 0:
			stats.ByConfidence["low"]++
		}

		for _, m := range ep.Methods {
			stats.ByMethod[string(m)]++
		}

		stats.BySource[string(ep.Source)]++

		if IsLowConfidence(ep.Path) {
			stats.LowConfidence++
		}
	}

	return stats
}

func (r *Report) SaveJSON(path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("api: marshal report: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("api: create report: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("api: write report: %w", err)
	}

	return nil
}

func (r *Report) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("api: marshal report: %w", err)
	}
	return string(data), nil
}

func ExportEndpointsJSON(endpoints []APIEndpoint, path string) error {
	data, err := json.MarshalIndent(endpoints, "", "  ")
	if err != nil {
		return fmt.Errorf("api: marshal endpoints: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (r ReportStats) sourceList() []string {
	var sources []string
	for s := range r.BySource {
		sources = append(sources, s)
	}
	return sources
}

func modeToString(mode DiscoveryMode) string {
	switch mode {
	case ModePassiveOnly:
		return "passive_only"
	case ModePassiveAndJS:
		return "passive_and_js"
	case ModeFull:
		return "full"
	default:
		return "unknown"
	}
}

func ExportJSON(target string, endpoints []APIEndpoint, mode DiscoveryMode, path string) error {
	report := GenerateReport(target, endpoints, mode)
	return report.SaveJSON(path)
}