package util

import (
	"encoding/json"
	"testing"
)

func TestExtractDiffsBasic(t *testing.T) {
	before := json.RawMessage(`{"name":"old","count":3}`)
	after := json.RawMessage(`{"name":"new","count":3}`)

	diffs := ExtractDiffs(before, after, nil, nil, 10)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d: %v", len(diffs), diffs)
	}
	if diffs[0].Path != "name" {
		t.Errorf("expected path 'name', got %q", diffs[0].Path)
	}
}

func TestExtractDiffsNewAndRemovedKeys(t *testing.T) {
	before := json.RawMessage(`{"old_key":"val"}`)
	after := json.RawMessage(`{"new_key":"val2"}`)

	diffs := ExtractDiffs(before, after, nil, nil, 10)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs, got %d: %v", len(diffs), diffs)
	}
}

func TestExtractDiffsSensitive(t *testing.T) {
	before := json.RawMessage(`{"password":"secret123","name":"test"}`)
	after := json.RawMessage(`{"password":"newsecret","name":"test"}`)
	sensitive := json.RawMessage(`{"password":true}`)

	diffs := ExtractDiffs(before, after, sensitive, nil, 10)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Before != "<sensitive>" || diffs[0].After != "<sensitive>" {
		t.Errorf("expected sensitive markers, got %q -> %q", diffs[0].Before, diffs[0].After)
	}
}

func TestExtractDiffsUnknown(t *testing.T) {
	before := json.RawMessage(`{"id":"old-id","name":"test"}`)
	after := json.RawMessage(`{"name":"test"}`)
	unknown := json.RawMessage(`{"id":true}`)

	diffs := ExtractDiffs(before, after, nil, unknown, 10)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].After != "<unknown>" {
		t.Errorf("expected <unknown>, got %q", diffs[0].After)
	}
}

func TestExtractDiffsMaxLimit(t *testing.T) {
	before := json.RawMessage(`{"a":"1","b":"2","c":"3"}`)
	after := json.RawMessage(`{"a":"x","b":"y","c":"z"}`)

	diffs := ExtractDiffs(before, after, nil, nil, 2)
	if len(diffs) != 2 {
		t.Fatalf("expected 2 diffs (max limit), got %d", len(diffs))
	}
}

func TestExtractDiffsNullBefore(t *testing.T) {
	after := json.RawMessage(`{"name":"new"}`)
	diffs := ExtractDiffs(nil, after, nil, nil, 10)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff for create, got %d", len(diffs))
	}
	if diffs[0].Before != "(not set)" {
		t.Errorf("expected '(not set)', got %q", diffs[0].Before)
	}
}

func TestExtractDiffsNullAfter(t *testing.T) {
	before := json.RawMessage(`{"name":"old"}`)
	diffs := ExtractDiffs(before, nil, nil, nil, 10)
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff for delete, got %d", len(diffs))
	}
	if diffs[0].After != "(removed)" {
		t.Errorf("expected '(removed)', got %q", diffs[0].After)
	}
}

func TestExtractReplacePaths(t *testing.T) {
	raw := json.RawMessage(`[["ami"],["tags","Name"]]`)
	paths := ExtractReplacePaths(raw)
	if len(paths) != 2 {
		t.Fatalf("expected 2 replace paths, got %d", len(paths))
	}
	if paths[0] != "ami" {
		t.Errorf("expected 'ami', got %q", paths[0])
	}
	if paths[1] != "tags.Name" {
		t.Errorf("expected 'tags.Name', got %q", paths[1])
	}
}

func TestExtractReplacePathsNull(t *testing.T) {
	paths := ExtractReplacePaths(nil)
	if paths != nil {
		t.Fatalf("expected nil for null input, got %v", paths)
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{nil, "null"},
		{"hello", `"hello"`},
		{float64(42), "42"},
		{float64(3.14), "3.14"},
		{true, "true"},
		{false, "false"},
	}

	for _, tt := range tests {
		got := formatValue(tt.input)
		if got != tt.want {
			t.Errorf("formatValue(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
