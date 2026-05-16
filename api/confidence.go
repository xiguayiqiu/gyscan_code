package api

func AdjustConfidence(ep *APIEndpoint) {
	if IsLowConfidence(ep.Path) {
		ep.Confidence -= 0.2
	}
	if IsAPIPath(ep.Path) {
		if ep.Confidence < 0.9 {
			ep.Confidence += 0.05
		}
	}
	if IsStaticResource(ep.Path) {
		ep.Confidence -= 0.5
	}
	if ep.SeenCount > 10 {
		if ep.Confidence < 0.95 {
			ep.Confidence += 0.05
		}
	}
	if ep.Confidence < 0 {
		ep.Confidence = 0
	}
	if ep.Confidence > 1.0 {
		ep.Confidence = 1.0
	}
}

func ClassifyConfidence(eps []APIEndpoint) []APIEndpoint {
	for i := range eps {
		AdjustConfidence(&eps[i])
	}
	return eps
}

func FilterByConfidence(eps []APIEndpoint, minConfidence Confidence) []APIEndpoint {
	var result []APIEndpoint
	for _, ep := range eps {
		if ep.Confidence >= minConfidence {
			result = append(result, ep)
		}
	}
	return result
}