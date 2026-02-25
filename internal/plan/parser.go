package plan

import (
	"encoding/json"
	"fmt"
	"io"
)

// Plan represents the top-level Terraform plan JSON structure
// as produced by `terraform show -json <planfile>`.
type Plan struct {
	FormatVersion   string           `json:"format_version"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// ResourceChange represents a single resource change in the plan.
type ResourceChange struct {
	Address      string `json:"address"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change holds the before/after state and action list.
type Change struct {
	Actions      Actions         `json:"actions"`
	Before       json.RawMessage `json:"before"`
	After        json.RawMessage `json:"after"`
	AfterUnknown json.RawMessage `json:"after_unknown"`
	// BeforeSensitive and AfterSensitive can be a bool or a map.
	BeforeSensitive json.RawMessage `json:"before_sensitive"`
	AfterSensitive  json.RawMessage `json:"after_sensitive"`
	ReplacePaths    json.RawMessage `json:"replace_paths"`
}

// Actions is a list of action strings (e.g., ["create"], ["update"], ["delete", "create"]).
type Actions []string

// ActionType returns the high-level action type for this change.
func (a Actions) ActionType() ActionKind {
	if len(a) == 0 {
		return ActionNoop
	}
	if len(a) == 1 {
		switch a[0] {
		case "create":
			return ActionCreate
		case "delete":
			return ActionDelete
		case "update":
			return ActionUpdate
		case "read":
			return ActionRead
		case "no-op":
			return ActionNoop
		}
	}
	if len(a) == 2 {
		if a[0] == "delete" && a[1] == "create" {
			return ActionReplace
		}
		if a[0] == "create" && a[1] == "delete" {
			return ActionReplace
		}
	}
	return ActionNoop
}

// ActionKind is the simplified action category.
type ActionKind int

const (
	ActionNoop ActionKind = iota
	ActionCreate
	ActionUpdate
	ActionDelete
	ActionReplace
	ActionRead
)

func (k ActionKind) String() string {
	switch k {
	case ActionCreate:
		return "create"
	case ActionUpdate:
		return "update"
	case ActionDelete:
		return "delete"
	case ActionReplace:
		return "replace"
	case ActionRead:
		return "read"
	default:
		return "no-op"
	}
}

// Parse reads a Terraform plan JSON from the given reader.
func Parse(r io.Reader) (*Plan, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input; expected Terraform plan JSON (from `terraform show -json <planfile>`)")
	}

	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing plan JSON: %w", err)
	}
	return &p, nil
}
