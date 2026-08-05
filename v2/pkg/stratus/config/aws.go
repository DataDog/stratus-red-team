package config

// AWSConfigImpl merges global AWS defaults with technique-specific settings
// before they are passed to Terraform.
type AWSConfigImpl struct {
	raw map[string]any
}

func (a *AWSConfigImpl) getMergedConfig(techniqueID string, vars SubstitutionVars) map[string]any {
	if a == nil || a.raw == nil {
		return nil
	}

	awsRaw := toStringMap(a.raw["aws"])
	merged := make(map[string]any)
	if defaultRaw := awsRaw["default"]; defaultRaw != nil {
		deepMerge(merged, cloneStringMap(defaultRaw))
	}
	techniques := toStringMap(awsRaw["techniques"])
	if techniqueRaw := techniques[techniqueID]; techniqueRaw != nil {
		deepMerge(merged, cloneStringMap(techniqueRaw))
	}
	if len(merged) == 0 {
		return nil
	}

	return substituteMap(merged, vars)
}

func cloneStringMap(value any) map[string]any {
	source := toStringMap(value)
	result := make(map[string]any, len(source))
	for key, item := range source {
		result[key] = cloneValue(item)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneStringMap(typed)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneValue(item)
		}
		return result
	default:
		return value
	}
}
