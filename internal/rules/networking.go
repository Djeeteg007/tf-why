package rules

import (
	"fmt"

	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/util"
)

var networkTypes = map[string]bool{
	"aws_route":              true,
	"aws_route_table":        true,
	"aws_network_acl":        true,
	"aws_lb_listener":        true,
	"aws_lb_listener_rule":   true,
	"aws_nat_gateway":        true,
}

// NetworkingRule detects risky networking resource changes.
type NetworkingRule struct{}

func (r *NetworkingRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if !networkTypes[rc.Type] {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action == plan.ActionNoop || action == plan.ActionRead || action == plan.ActionCreate {
		return nil
	}

	diffs := util.ExtractDiffs(
		rc.Change.Before, rc.Change.After,
		rc.Change.AfterSensitive, rc.Change.AfterUnknown, 10,
	)
	var whys []string
	for _, d := range diffs {
		whys = append(whys, d.String())
	}
	replacePaths := util.ExtractReplacePaths(rc.Change.ReplacePaths)
	for _, rp := range replacePaths {
		whys = append(whys, fmt.Sprintf("replace triggered by: %s", rp))
	}

	if action == plan.ActionReplace || action == plan.ActionDelete {
		if len(whys) == 0 {
			whys = []string{fmt.Sprintf("Networking resource will be %sd", action)}
		}
		return []RuleFinding{{
			Severity: SeverityHigh,
			Tags:     []string{"network"},
			Title:    fmt.Sprintf("Networking resource %s will be %sd", rc.Address, action),
			Address:  rc.Address,
			Why:      whys,
			Recommendations: []string{
				"Verify network connectivity will not be disrupted",
				"Plan for potential service interruption",
				"Confirm dependent services can tolerate the change",
			},
		}}
	}

	// Update — only if there are actual diffs.
	if action == plan.ActionUpdate && len(diffs) > 0 {
		return []RuleFinding{{
			Severity: SeverityMedium,
			Tags:     []string{"network"},
			Title:    fmt.Sprintf("Networking resource %s will be updated", rc.Address),
			Address:  rc.Address,
			Why:      whys,
			Recommendations: []string{
				"Review network attribute changes for connectivity impact",
			},
		}}
	}

	return nil
}
