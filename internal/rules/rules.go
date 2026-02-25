package rules

import (
	"github.com/djeeteg007/tf-why/internal/plan"
)

// Severity levels matching analysis.Severity.
const (
	SeverityLow    = 1
	SeverityMedium = 2
	SeverityHigh   = 3
)

// RuleFinding is an intermediate finding produced by a rule.
type RuleFinding struct {
	Severity        int
	Tags            []string
	Title           string
	Address         string
	Why             []string
	Recommendations []string
}

// Rule evaluates a single resource change and returns any findings.
type Rule interface {
	Evaluate(rc plan.ResourceChange) []RuleFinding
}

// AllRules returns all registered rules in evaluation order.
func AllRules() []Rule {
	return []Rule{
		&IAMPolicyRule{},
		&SecurityGroupRule{},
		&RDSRule{},
		&ECSRule{},
		&NetworkingRule{},
		&KMSRule{},
		&GenericRule{}, // generic rules run last as catch-all
	}
}
