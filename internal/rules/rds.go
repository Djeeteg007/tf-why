package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/util"
)

var rdsTypes = map[string]bool{
	"aws_db_instance":          true,
	"aws_rds_cluster":          true,
	"aws_rds_cluster_instance": true,
}

// RDSRule detects risky RDS changes.
type RDSRule struct{}

func (r *RDSRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if !rdsTypes[rc.Type] {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action == plan.ActionNoop || action == plan.ActionRead {
		return nil
	}

	var findings []RuleFinding

	if action == plan.ActionReplace {
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
		if len(whys) == 0 {
			whys = []string{"Database resource will be destroyed and recreated"}
		}

		findings = append(findings, RuleFinding{
			Severity: SeverityHigh,
			Tags:     []string{"downtime", "data"},
			Title:    fmt.Sprintf("Database %s will be replaced — potential data loss", rc.Address),
			Address:  rc.Address,
			Why:      whys,
			Recommendations: []string{
				"Take a snapshot before applying",
				"Confirm rollback plan; expect downtime",
				"Verify data migration strategy",
			},
		})
	}

	if action == plan.ActionUpdate || action == plan.ActionReplace {
		findings = append(findings, r.checkEngineVersion(rc)...)
	}

	return findings
}

func (r *RDSRule) checkEngineVersion(rc plan.ResourceChange) []RuleFinding {
	var beforeMap, afterMap map[string]interface{}
	if len(rc.Change.Before) > 0 && string(rc.Change.Before) != "null" {
		_ = json.Unmarshal(rc.Change.Before, &beforeMap)
	}
	if len(rc.Change.After) > 0 && string(rc.Change.After) != "null" {
		_ = json.Unmarshal(rc.Change.After, &afterMap)
	}

	if beforeMap == nil || afterMap == nil {
		return nil
	}

	beforeVersion, _ := beforeMap["engine_version"].(string)
	afterVersion, _ := afterMap["engine_version"].(string)

	if beforeVersion == "" || afterVersion == "" || beforeVersion == afterVersion {
		return nil
	}

	severity := SeverityMedium
	title := fmt.Sprintf("Database engine version change on %s", rc.Address)

	if isMajorVersionBump(beforeVersion, afterVersion) {
		severity = SeverityHigh
		title = fmt.Sprintf("Major database engine version upgrade on %s", rc.Address)
	}

	return []RuleFinding{{
		Severity: severity,
		Tags:     []string{"downtime"},
		Title:    title,
		Address:  rc.Address,
		Why: []string{
			fmt.Sprintf("engine_version: %q → %q", beforeVersion, afterVersion),
		},
		Recommendations: []string{
			"Test the upgrade in a staging environment first",
			"Review engine changelog for breaking changes",
			"Schedule during maintenance window",
		},
	}}
}

// isMajorVersionBump checks if the major version prefix differs.
func isMajorVersionBump(before, after string) bool {
	beforeMajor := majorVersion(before)
	afterMajor := majorVersion(after)
	return beforeMajor != "" && afterMajor != "" && beforeMajor != afterMajor
}

func majorVersion(version string) string {
	parts := strings.SplitN(version, ".", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
