package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/djeeteg007/tf-why/internal/analysis"
)

// Text renders the analysis result as human-readable text.
func Text(w io.Writer, result analysis.Result) {
	// Summary
	s := result.Summary
	fmt.Fprintf(w, "Plan Summary: %d to create, %d to update, %d to delete, %d to replace\n",
		s.Create, s.Update, s.Delete, s.Replace)

	if len(result.Findings) == 0 {
		fmt.Fprintln(w, "\nNo findings.")
		return
	}

	fmt.Fprintf(w, "Overall Severity: %s\n", strings.ToUpper(result.OverallSeverity.String()))
	fmt.Fprintf(w, "\n%d finding(s):\n", len(result.Findings))

	for i, f := range result.Findings {
		fmt.Fprintf(w, "\n─── %d. [%s] %s ───\n", i+1, strings.ToUpper(f.Severity.String()), f.Title)
		fmt.Fprintf(w, "  Resource: %s\n", f.Address)
		fmt.Fprintf(w, "  Tags:     %s\n", strings.Join(f.Tags, ", "))

		if len(f.Why) > 0 {
			fmt.Fprintln(w, "  Why:")
			for _, reason := range f.Why {
				fmt.Fprintf(w, "    - %s\n", reason)
			}
		}

		if len(f.Recommendations) > 0 {
			fmt.Fprintln(w, "  Recommendations:")
			for _, rec := range f.Recommendations {
				fmt.Fprintf(w, "    [ ] %s\n", rec)
			}
		}
	}
}
