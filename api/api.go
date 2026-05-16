package api

import "fmt"

type Confidence float64

const (
	ConfidenceTraffic Confidence = 1.0
	ConfidenceJSParse Confidence = 0.8
	ConfidenceProbe   Confidence = 0.6
	ConfidenceUnknown Confidence = 0.3
)

type SourceType string

const (
	SourceTraffic     SourceType = "traffic"
	SourceJSParse     SourceType = "js_parse"
	SourceActiveProbe SourceType = "active_probe"
)

type HTTPMethod string

const (
	MethodGET     HTTPMethod = "GET"
	MethodPOST    HTTPMethod = "POST"
	MethodPUT     HTTPMethod = "PUT"
	MethodDELETE  HTTPMethod = "DELETE"
	MethodPATCH   HTTPMethod = "PATCH"
	MethodOPTIONS HTTPMethod = "OPTIONS"
	MethodHEAD    HTTPMethod = "HEAD"
)

type Parameter struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Location string `json:"location"`
	Required bool   `json:"required"`
}

type APIEndpoint struct {
	Path        string       `json:"path"`
	Methods     []HTTPMethod `json:"methods"`
	Host        string       `json:"host"`
	Port        int          `json:"port"`
	Confidence  Confidence   `json:"confidence"`
	Source      SourceType   `json:"source"`
	Parameters  []Parameter  `json:"parameters,omitempty"`
	ContentType string       `json:"content_type,omitempty"`
	StatusCode  int          `json:"status_code,omitempty"`
	SeenCount   int          `json:"seen_count"`
}

type APIAssetList struct {
	Target     string        `json:"target"`
	TotalCount int           `json:"total_count"`
	Endpoints  []APIEndpoint `json:"endpoints"`
	Sources    []SourceType  `json:"sources"`
}

type DiscoveryMode int

const (
	ModePassiveOnly DiscoveryMode = iota
	ModePassiveAndJS
	ModeFull
)

type DiscoveryConfig struct {
	Target      string
	Mode        DiscoveryMode
	PcapPaths   []string
	JSPaths     []string
	ActiveProbe bool
	ProbeLimit  int
	AllowHTTP   bool
	RateLimit   int
	IncludeHost string
	TLSKeyLog   string
}

func DefaultConfig(target string) *DiscoveryConfig {
	return &DiscoveryConfig{
		Target:     target,
		Mode:       ModePassiveAndJS,
		ProbeLimit: 1000,
		RateLimit:  10,
		AllowHTTP:  false,
	}
}

type DiscoveryEngine struct {
	config    *DiscoveryConfig
	endpoints []APIEndpoint
}

func NewDiscoveryEngine(cfg *DiscoveryConfig) *DiscoveryEngine {
	if cfg == nil {
		cfg = DefaultConfig("")
	}
	if cfg.ProbeLimit <= 0 {
		cfg.ProbeLimit = 1000
	}
	return &DiscoveryEngine{config: cfg}
}

func (e *DiscoveryEngine) Run() (*APIAssetList, error) {
	if e.config.Target == "" {
		return nil, fmt.Errorf("api: target is required")
	}

	if e.config.Mode == ModePassiveOnly || e.config.Mode == ModePassiveAndJS || e.config.Mode == ModeFull {
		if len(e.config.PcapPaths) > 0 {
			passiveEndpoints, err := DiscoverFromPcap(e.config)
			if err != nil {
				return nil, fmt.Errorf("api: passive discovery: %w", err)
			}
			for i := range passiveEndpoints {
				passiveEndpoints[i].Source = SourceTraffic
				passiveEndpoints[i].Confidence = ConfidenceTraffic
			}
			e.endpoints = append(e.endpoints, passiveEndpoints...)
		}
	}

	if e.config.Mode == ModePassiveAndJS || e.config.Mode == ModeFull {
		if len(e.config.JSPaths) > 0 {
			jsEndpoints, err := DiscoverFromJS(e.config)
			if err != nil {
				return nil, fmt.Errorf("api: js discovery: %w", err)
			}
			for i := range jsEndpoints {
				jsEndpoints[i].Source = SourceJSParse
				jsEndpoints[i].Confidence = ConfidenceJSParse
			}
			e.endpoints = append(e.endpoints, jsEndpoints...)
		}
	}

	if e.config.Mode == ModeFull && e.config.ActiveProbe {
		probeEndpoints, err := DiscoverActive(e.config, e.endpoints)
		if err != nil {
			return nil, fmt.Errorf("api: active discovery: %w", err)
		}
		for i := range probeEndpoints {
			probeEndpoints[i].Source = SourceActiveProbe
			probeEndpoints[i].Confidence = ConfidenceProbe
		}
		e.endpoints = append(e.endpoints, probeEndpoints...)
	}

	e.endpoints = Deduplicate(e.endpoints)
	e.endpoints = NormalizePaths(e.endpoints)

	sources := collectSources(e.endpoints)
	return &APIAssetList{
		Target:     e.config.Target,
		TotalCount: len(e.endpoints),
		Endpoints:  e.endpoints,
		Sources:    sources,
	}, nil
}

func (e *DiscoveryEngine) GetEndpoints() []APIEndpoint {
	return e.endpoints
}

func (e *DiscoveryEngine) AddEndpoints(eps []APIEndpoint) {
	e.endpoints = append(e.endpoints, eps...)
}

func collectSources(eps []APIEndpoint) []SourceType {
	seen := make(map[SourceType]bool)
	var result []SourceType
	for _, ep := range eps {
		if !seen[ep.Source] {
			seen[ep.Source] = true
			result = append(result, ep.Source)
		}
	}
	return result
}
