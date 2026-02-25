package util

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Diff represents a single attribute difference between before and after.
type Diff struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func (d Diff) String() string {
	return fmt.Sprintf("%s: %s → %s", d.Path, d.Before, d.After)
}

// ExtractDiffs computes the top-level and nested attribute differences
// between before and after JSON blobs, respecting sensitive and unknown markers.
// Returns at most maxDiffs entries.
func ExtractDiffs(before, after, afterSensitive, afterUnknown json.RawMessage, maxDiffs int) []Diff {
	var beforeMap map[string]interface{}
	var afterMap map[string]interface{}
	sensitiveSet := parseSensitiveSet(afterSensitive)
	unknownSet := parseUnknownSet(afterUnknown)

	if len(before) > 0 && string(before) != "null" {
		_ = json.Unmarshal(before, &beforeMap)
	}
	if len(after) > 0 && string(after) != "null" {
		_ = json.Unmarshal(after, &afterMap)
	}

	// For delete: after is nil, show deleted keys.
	// For create: before is nil, show created keys.
	if beforeMap == nil && afterMap == nil {
		return nil
	}

	var diffs []Diff

	// Collect all keys from both maps.
	allKeys := make(map[string]bool)
	for k := range beforeMap {
		allKeys[k] = true
	}
	for k := range afterMap {
		allKeys[k] = true
	}

	sortedKeys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, key := range sortedKeys {
		if maxDiffs > 0 && len(diffs) >= maxDiffs {
			break
		}

		bVal, bOk := beforeMap[key]
		aVal, aOk := afterMap[key]

		if sensitiveSet[key] {
			if bOk && aOk {
				bStr := "<sensitive>"
				aStr := "<sensitive>"
				diffs = append(diffs, Diff{Path: key, Before: bStr, After: aStr})
			} else if aOk {
				diffs = append(diffs, Diff{Path: key, Before: "(not set)", After: "<sensitive>"})
			} else if bOk {
				diffs = append(diffs, Diff{Path: key, Before: "<sensitive>", After: "(removed)"})
			}
			continue
		}

		if unknownSet[key] {
			bStr := formatValue(bVal)
			if !bOk {
				bStr = "(not set)"
			}
			diffs = append(diffs, Diff{Path: key, Before: bStr, After: "<unknown>"})
			continue
		}

		if !bOk {
			// New key
			diffs = append(diffs, Diff{Path: key, Before: "(not set)", After: formatValue(aVal)})
			continue
		}
		if !aOk {
			// Removed key
			diffs = append(diffs, Diff{Path: key, Before: formatValue(bVal), After: "(removed)"})
			continue
		}

		bJSON, _ := json.Marshal(bVal)
		aJSON, _ := json.Marshal(aVal)
		if string(bJSON) != string(aJSON) {
			diffs = append(diffs, Diff{Path: key, Before: formatValue(bVal), After: formatValue(aVal)})
		}
	}

	return diffs
}

// ExtractReplacePaths parses the replace_paths field from the change.
func ExtractReplacePaths(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	// replace_paths is typically [][]string or [][]interface{}
	var paths [][]interface{}
	if err := json.Unmarshal(raw, &paths); err != nil {
		return nil
	}
	var result []string
	for _, segments := range paths {
		parts := make([]string, len(segments))
		for i, seg := range segments {
			parts[i] = fmt.Sprintf("%v", seg)
		}
		result = append(result, strings.Join(parts, "."))
	}
	return result
}

// parseSensitiveSet parses the *_sensitive field which can be:
// - a bool (true means everything is sensitive)
// - a map of key->bool or key->map (nested)
func parseSensitiveSet(raw json.RawMessage) map[string]bool {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	// Try bool first
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if b {
			// Everything is sensitive — we can't enumerate keys here,
			// but the caller will handle this.
			return map[string]bool{"*": true}
		}
		return nil
	}
	// Try map
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		result := make(map[string]bool, len(m))
		for k, v := range m {
			// If the value is `true`, mark as sensitive.
			var bv bool
			if json.Unmarshal(v, &bv) == nil && bv {
				result[k] = true
			} else {
				// Nested object also means sensitive.
				result[k] = true
			}
		}
		return result
	}
	return nil
}

func parseUnknownSet(raw json.RawMessage) map[string]bool {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		if b {
			return map[string]bool{"*": true}
		}
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err == nil {
		result := make(map[string]bool, len(m))
		for k, v := range m {
			var bv bool
			if json.Unmarshal(v, &bv) == nil && bv {
				result[k] = true
			}
		}
		return result
	}
	return nil
}

func formatValue(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case map[string]interface{}, []interface{}:
		b, _ := json.Marshal(val)
		s := string(b)
		if len(s) > 120 {
			return s[:117] + "..."
		}
		return s
	default:
		return fmt.Sprintf("%v", val)
	}
}

// GetNestedValue retrieves a value from a parsed JSON object by dot-separated path.
func GetNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = data
	for _, part := range parts {
		switch m := current.(type) {
		case map[string]interface{}:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}
	return current, true
}
