package rules

import (
	"fmt"

	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/util"
)

// GenericRule handles replace and delete for any resource type.
type GenericRule struct{}

func (r *GenericRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	action := rc.Change.Actions.ActionType()

	// Only fire for replace/delete that aren't already handled by specific rules.
	if action != plan.ActionReplace && action != plan.ActionDelete {
		return nil
	}

	// Skip types that have their own dedicated rules to avoid duplicate findings.
	if isHandledBySpecificRule(rc.Type, action) {
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

	if action == plan.ActionReplace {
		if len(whys) == 0 {
			whys = []string{"Resource will be destroyed and recreated"}
		}
		return []RuleFinding{{
			Severity: SeverityHigh,
			Tags:     []string{"downtime"},
			Title:    fmt.Sprintf("Resource %s will be replaced (destroy + recreate)", rc.Address),
			Address:  rc.Address,
			Why:      whys,
			Recommendations: []string{
				"Confirm rollback plan; expect downtime",
				"Verify no dependent resources will break",
			},
		}}
	}

	// Delete
	if len(whys) == 0 {
		whys = []string{"Resource will be destroyed"}
	}
	return []RuleFinding{{
		Severity: SeverityHigh,
		Tags:     []string{"ops"},
		Title:    fmt.Sprintf("Resource %s will be deleted", rc.Address),
		Address:  rc.Address,
		Why:      whys,
		Recommendations: []string{
			"Confirm resource is safe to destroy",
			"Check for dependent resources or data loss",
		},
	}}
}

// isHandledBySpecificRule returns true if the resource type + action
// is already covered by a specific rule (to avoid duplicate findings).
func isHandledBySpecificRule(resourceType string, action plan.ActionKind) bool {
	switch resourceType {
	// RDS resources — RDSRule handles replace
	case "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance":
		if action == plan.ActionReplace {
			return true
		}
	// Networking resources — NetworkingRule handles replace/delete
	case "aws_route", "aws_route_table", "aws_network_acl",
		"aws_lb_listener", "aws_lb_listener_rule", "aws_nat_gateway":
		return true
	// KMS resources — KMSRule handles replace/delete
	case "aws_kms_key", "aws_kms_alias":
		return true
	}
	return false
}
