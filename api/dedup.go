package api

import "sort"

func Deduplicate(endpoints []APIEndpoint) []APIEndpoint {
	type key struct {
		path   string
		host   string
		port   int
		method HTTPMethod
	}

	merged := make(map[key]*APIEndpoint)

	for i := range endpoints {
		ep := &endpoints[i]
		for _, m := range ep.Methods {
			k := key{path: ep.Path, host: ep.Host, port: ep.Port, method: m}
			if existing, ok := merged[k]; ok {
				existing.SeenCount += ep.SeenCount
				if ep.Confidence > existing.Confidence {
					existing.Confidence = ep.Confidence
					existing.Source = ep.Source
				}
				if len(ep.Parameters) > len(existing.Parameters) {
					existing.Parameters = ep.Parameters
				}
			} else {
				clone := *ep
				clone.Methods = []HTTPMethod{m}
				merged[k] = &clone
			}
		}
	}

	pathMethod := make(map[string]map[HTTPMethod]*APIEndpoint)
	for k, ep := range merged {
		if _, ok := pathMethod[ep.Path]; !ok {
			pathMethod[ep.Path] = make(map[HTTPMethod]*APIEndpoint)
		}
		if existing, ok := pathMethod[ep.Path][k.method]; ok {
			if ep.Confidence > existing.Confidence {
				pathMethod[ep.Path][k.method] = ep
			}
		} else {
			pathMethod[ep.Path][k.method] = ep
		}
	}

	var result []APIEndpoint
	for _, methods := range pathMethod {
		for _, ep := range methods {
			if !IsStaticResource(ep.Path) || ep.Confidence > 0.8 {
				result = append(result, *ep)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Confidence != result[j].Confidence {
			return result[i].Confidence > result[j].Confidence
		}
		if result[i].SeenCount != result[j].SeenCount {
			return result[i].SeenCount > result[j].SeenCount
		}
		return result[i].Path < result[j].Path
	})

	return result
}

func MergeEndpoints(a, b []APIEndpoint) []APIEndpoint {
	return Deduplicate(append(a, b...))
}