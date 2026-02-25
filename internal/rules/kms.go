package rules

import (
	"fmt"

	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/util"
)

var kmsTypes = map[string]bool{
	"aws_kms_key":   true,
	"aws_kms_alias": true,
}

// KMSRule detects risky KMS key/alias changes.
type KMSRule struct{}

func (r *KMSRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if !kmsTypes[rc.Type] {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action != plan.ActionReplace && action != plan.ActionDelete {
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
	if len(whys) == 0 {
		whys = []string{fmt.Sprintf("KMS resource will be %sd", action)}
	}

	return []RuleFinding{{
		Severity: SeverityHigh,
		Tags:     []string{"security", "ops"},
		Title:    fmt.Sprintf("KMS resource %s will be %sd — encrypted data at risk", rc.Address, action),
		Address:  rc.Address,
		Why:      whys,
		Recommendations: []string{
			"Verify no data is encrypted with this key before destroying",
			"Consider scheduling key deletion with a waiting period",
			"Ensure key aliases are updated if key is being replaced",
		},
	}}
}
