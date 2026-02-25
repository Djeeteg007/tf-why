package analysis

import (
	"sort"
	"strings"

	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/rules"
)

// Severity levels in increasing order.
type Severity int

const (
	SeverityLow    Severity = 1
	SeverityMedium Severity = 2
	SeverityHigh   Severity = 3
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	default:
		return "unknown"
	}
}

func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	default:
		return SeverityLow
	}
}

// Finding is a single analysis finding.
type Finding struct {
	Severity        Severity `json:"severity"`
	Tags            []string `json:"tags"`
	Title           string   `json:"title"`
	Address         string   `json:"address"`
	Why             []string `json:"why"`
	Recommendations []string `json:"recommendations"`
}

// Summary holds aggregate counts.
type Summary struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Delete  int `json:"delete"`
	Replace int `json:"replace"`
}

// Result is the complete analysis output.
type Result struct {
	Summary         Summary  `json:"summary"`
	Findings        []Finding `json:"findings"`
	OverallSeverity Severity `json:"overall_severity"`
}

// Options controls filtering and limits.
type Options struct {
	OnlyTypes   []string // filter to these resource types
	ExcludeTags []string // exclude findings with any of these tags
	MaxFindings int      // max number of findings to return
}

// Analyze runs all rules against the plan and returns the result.
func Analyze(p *plan.Plan, opts Options) Result {
	summary := computeSummary(p)

	allRules := rules.AllRules()

	var findings []Finding
	for _, rc := range p.ResourceChanges {
		action := rc.Change.Actions.ActionType()
		if action == plan.ActionNoop || action == plan.ActionRead {
			continue
		}

		if len(opts.OnlyTypes) > 0 && !containsStr(opts.OnlyTypes, rc.Type) {
			continue
		}

		for _, rule := range allRules {
			ruleFindings := rule.Evaluate(rc)
			for _, rf := range ruleFindings {
				findings = append(findings, Finding{
					Severity:        Severity(rf.Severity),
					Tags:            rf.Tags,
					Title:           rf.Title,
					Address:         rf.Address,
					Why:             rf.Why,
					Recommendations: rf.Recommendations,
				})
			}
		}
	}

	// Filter by excluded tags.
	if len(opts.ExcludeTags) > 0 {
		findings = filterByExcludedTags(findings, opts.ExcludeTags)
	}

	// Sort: severity desc, then address asc for deterministic ordering.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Address < findings[j].Address
	})

	// Apply max findings.
	maxFindings := opts.MaxFindings
	if maxFindings <= 0 {
		maxFindings = 20
	}
	if len(findings) > maxFindings {
		findings = findings[:maxFindings]
	}

	// Compute overall severity.
	var overall Severity
	for _, f := range findings {
		if f.Severity > overall {
			overall = f.Severity
		}
	}

	return Result{
		Summary:         summary,
		Findings:        findings,
		OverallSeverity: overall,
	}
}

func computeSummary(p *plan.Plan) Summary {
	var s Summary
	for _, rc := range p.ResourceChanges {
		switch rc.Change.Actions.ActionType() {
		case plan.ActionCreate:
			s.Create++
		case plan.ActionUpdate:
			s.Update++
		case plan.ActionDelete:
			s.Delete++
		case plan.ActionReplace:
			s.Replace++
		}
	}
	return s
}

func containsStr(list []string, item string) bool {
	for _, s := range list {
		if s == item {
			return true
		}
	}
	return false
}

func filterByExcludedTags(findings []Finding, excludeTags []string) []Finding {
	excludeSet := make(map[string]bool, len(excludeTags))
	for _, t := range excludeTags {
		excludeSet[t] = true
	}

	var result []Finding
	for _, f := range findings {
		excluded := false
		for _, tag := range f.Tags {
			if excludeSet[tag] {
				excluded = true
				break
			}
		}
		if !excluded {
			result = append(result, f)
		}
	}
	return result
}
