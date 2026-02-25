package plan

import (
	"strings"
	"testing"
)

func TestParseEmpty(t *testing.T) {
	_, err := Parse(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for empty input")
	}
	if !strings.Contains(err.Error(), "empty input") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := Parse(strings.NewReader("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseMinimalPlan(t *testing.T) {
	input := `{
		"format_version": "1.0",
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {"ami": "ami-123"}
				}
			}
		]
	}`

	p, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.ResourceChanges) != 1 {
		t.Fatalf("expected 1 resource change, got %d", len(p.ResourceChanges))
	}
	rc := p.ResourceChanges[0]
	if rc.Address != "aws_instance.web" {
		t.Errorf("expected address aws_instance.web, got %s", rc.Address)
	}
	if rc.Type != "aws_instance" {
		t.Errorf("expected type aws_instance, got %s", rc.Type)
	}
}

func TestActionsActionType(t *testing.T) {
	tests := []struct {
		actions Actions
		want    ActionKind
	}{
		{Actions{"create"}, ActionCreate},
		{Actions{"update"}, ActionUpdate},
		{Actions{"delete"}, ActionDelete},
		{Actions{"delete", "create"}, ActionReplace},
		{Actions{"create", "delete"}, ActionReplace},
		{Actions{"no-op"}, ActionNoop},
		{Actions{"read"}, ActionRead},
		{Actions{}, ActionNoop},
	}

	for _, tt := range tests {
		got := tt.actions.ActionType()
		if got != tt.want {
			t.Errorf("Actions%v.ActionType() = %v, want %v", tt.actions, got, tt.want)
		}
	}
}

func TestActionKindString(t *testing.T) {
	tests := []struct {
		kind ActionKind
		want string
	}{
		{ActionCreate, "create"},
		{ActionUpdate, "update"},
		{ActionDelete, "delete"},
		{ActionReplace, "replace"},
		{ActionRead, "read"},
		{ActionNoop, "no-op"},
	}

	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("ActionKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}
