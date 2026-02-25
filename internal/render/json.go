package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/djeeteg007/tf-why/internal/analysis"
)

type jsonOutput struct {
	Summary         analysis.Summary   `json:"summary"`
	OverallSeverity string             `json:"overall_severity"`
	FindingsCount   int                `json:"findings_count"`
	Findings        []jsonFinding      `json:"findings"`
}

type jsonFinding struct {
	Severity        string   `json:"severity"`
	Tags            []string `json:"tags"`
	Title           string   `json:"title"`
	Address         string   `json:"address"`
	Why             []string `json:"why"`
	Recommendations []string `json:"recommendations"`
}

// JSON renders the analysis result as machine-readable JSON.
func JSON(w io.Writer, result analysis.Result) error {
	findings := make([]jsonFinding, len(result.Findings))
	for i, f := range result.Findings {
		findings[i] = jsonFinding{
			Severity:        f.Severity.String(),
			Tags:            f.Tags,
			Title:           f.Title,
			Address:         f.Address,
			Why:             f.Why,
			Recommendations: f.Recommendations,
		}
	}

	out := jsonOutput{
		Summary:         result.Summary,
		OverallSeverity: result.OverallSeverity.String(),
		FindingsCount:   len(result.Findings),
		Findings:        findings,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}
	return nil
}
