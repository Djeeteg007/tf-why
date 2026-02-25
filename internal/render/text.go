package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/djeeteg007/tf-why/internal/analysis"
)

// Text renders the analysis result as human-readable colored text.
func Text(w io.Writer, result analysis.Result) {
	s := result.Summary
	total := s.Create + s.Update + s.Delete + s.Replace

	// Header
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", cb(brightWhite, "TERRAFORM PLAN ANALYSIS"))
	fmt.Fprintf(w, "  %s\n", c(dim, strings.Repeat("─", 50)))

	// Summary bar
	fmt.Fprintln(w)
	if total == 0 {
		fmt.Fprintf(w, "  %s  No resource changes detected\n", c(dim, "∅"))
	} else {
		fmt.Fprintf(w, "  %s  ", c(dim, "CHANGES"))
		parts := []string{}
		if s.Create > 0 {
			parts = append(parts, cb(green, fmt.Sprintf("+%d create", s.Create)))
		}
		if s.Update > 0 {
			parts = append(parts, cb(yellow, fmt.Sprintf("~%d update", s.Update)))
		}
		if s.Delete > 0 {
			parts = append(parts, cb(red, fmt.Sprintf("-%d delete", s.Delete)))
		}
		if s.Replace > 0 {
			parts = append(parts, cb(brightRed, fmt.Sprintf("!%d replace", s.Replace)))
		}
		fmt.Fprintln(w, strings.Join(parts, c(dim, "  |  ")))
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  %s  %s\n", c(brightGreen, "✓"), c(brightGreen, "No findings — plan looks safe"))
		fmt.Fprintln(w)
		return
	}

	// Overall severity
	sev := strings.ToUpper(result.OverallSeverity.String())
	fmt.Fprintf(w, "  %s  %s %s\n",
		c(dim, "RISK"),
		severityBadge(sev),
		c(dim, fmt.Sprintf("(%d finding%s)", len(result.Findings), plural(len(result.Findings)))))
	fmt.Fprintln(w)

	// Findings
	for i, f := range result.Findings {
		renderFinding(w, i+1, f)
	}
}

func renderFinding(w io.Writer, num int, f analysis.Finding) {
	sev := strings.ToUpper(f.Severity.String())
	sevCol := severityColor(sev)

	// Top border with severity badge
	fmt.Fprintf(w, "  %s %s  %s\n",
		severityBadge(sev),
		c(dim, fmt.Sprintf("#%d", num)),
		cb(sevCol, f.Title))

	// Resource address
	fmt.Fprintf(w, "  %s  %s %s\n",
		c(dim, "│"),
		c(dim, "Resource:"),
		cb(cyan, f.Address))

	// Tags
	if len(f.Tags) > 0 {
		tagParts := make([]string, len(f.Tags))
		for i, tag := range f.Tags {
			tagParts[i] = c(tagColor(tag), tag)
		}
		fmt.Fprintf(w, "  %s  %s %s\n",
			c(dim, "│"),
			c(dim, "Tags:"),
			strings.Join(tagParts, c(dim, ", ")))
	}

	// Why
	if len(f.Why) > 0 {
		fmt.Fprintf(w, "  %s\n", c(dim, "│"))
		fmt.Fprintf(w, "  %s  %s\n", c(dim, "│"), cb(white, "Why:"))
		for _, reason := range f.Why {
			fmt.Fprintf(w, "  %s  %s %s\n",
				c(dim, "│"),
				c(sevCol, "→"),
				reason)
		}
	}

	// Recommendations
	if len(f.Recommendations) > 0 {
		fmt.Fprintf(w, "  %s\n", c(dim, "│"))
		fmt.Fprintf(w, "  %s  %s\n", c(dim, "│"), cb(white, "Recommendations:"))
		for _, rec := range f.Recommendations {
			fmt.Fprintf(w, "  %s  %s %s\n",
				c(dim, "│"),
				c(dim, "□"),
				c(white, rec))
		}
	}

	// Bottom spacing
	fmt.Fprintln(w)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
