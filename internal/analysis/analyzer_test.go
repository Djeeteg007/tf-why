package analysis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/djeeteg007/tf-why/internal/plan"
)

func loadFixture(t *testing.T, name string) *plan.Plan {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("cannot open fixture %s: %v", name, err)
	}
	defer f.Close()
	p, err := plan.Parse(f)
	if err != nil {
		t.Fatalf("cannot parse fixture %s: %v", name, err)
	}
	return p
}

func TestAnalyzeSummary(t *testing.T) {
	p := loadFixture(t, "generic_replace.json")
	result := Analyze(p, Options{MaxFindings: 20})
	if result.Summary.Replace != 1 {
		t.Errorf("expected 1 replace, got %d", result.Summary.Replace)
	}
}

func TestAnalyzeOnlyFilter(t *testing.T) {
	p := loadFixture(t, "generic_replace.json")
	result := Analyze(p, Options{
		OnlyTypes:   []string{"aws_s3_bucket"}, // not aws_instance
		MaxFindings: 20,
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings with mismatched filter, got %d", len(result.Findings))
	}
}

func TestAnalyzeExcludeTag(t *testing.T) {
	p := loadFixture(t, "generic_replace.json")
	result := Analyze(p, Options{
		ExcludeTags: []string{"downtime"},
		MaxFindings: 20,
	})
	for _, f := range result.Findings {
		for _, tag := range f.Tags {
			if tag == "downtime" {
				t.Error("finding with excluded tag 'downtime' was not filtered")
			}
		}
	}
}

func TestAnalyzeMaxFindings(t *testing.T) {
	// Use a fixture that generates many findings
	p := loadFixture(t, "sg_inline_multi.json")
	result := Analyze(p, Options{MaxFindings: 2})
	if len(result.Findings) > 2 {
		t.Errorf("expected at most 2 findings, got %d", len(result.Findings))
	}
}

func TestAnalyzeOverallSeverity(t *testing.T) {
	p := loadFixture(t, "iam_wildcard.json")
	result := Analyze(p, Options{MaxFindings: 20})
	if result.OverallSeverity != SeverityHigh {
		t.Errorf("expected HIGH overall severity, got %s", result.OverallSeverity)
	}
}

func TestAnalyzeDeterministicOrdering(t *testing.T) {
	p := loadFixture(t, "iam_passrole.json")
	// Run multiple times to check determinism
	var firstTitles []string
	for i := 0; i < 5; i++ {
		result := Analyze(p, Options{MaxFindings: 20})
		titles := make([]string, len(result.Findings))
		for j, f := range result.Findings {
			titles[j] = f.Title
		}
		if i == 0 {
			firstTitles = titles
		} else {
			if len(titles) != len(firstTitles) {
				t.Fatalf("non-deterministic finding count on run %d", i)
			}
			for j := range titles {
				if titles[j] != firstTitles[j] {
					t.Errorf("non-deterministic ordering on run %d, position %d: %q vs %q",
						i, j, titles[j], firstTitles[j])
				}
			}
		}
	}
}

func TestAnalyzeNoChanges(t *testing.T) {
	p := loadFixture(t, "no_changes.json")
	result := Analyze(p, Options{MaxFindings: 20})
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for no-op, got %d", len(result.Findings))
	}
	if result.OverallSeverity != 0 {
		t.Errorf("expected severity 0 for no-op, got %d", result.OverallSeverity)
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"low", SeverityLow},
		{"LOW", SeverityLow},
		{"medium", SeverityMedium},
		{"Medium", SeverityMedium},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"unknown", SeverityLow},
	}
	for _, tt := range tests {
		got := ParseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
