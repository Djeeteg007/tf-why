package rules

import (
	"encoding/json"
	"fmt"

	"github.com/djeeteg007/tf-why/internal/plan"
)

// ECSRule detects risky ECS service changes.
type ECSRule struct{}

func (r *ECSRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if rc.Type != "aws_ecs_service" {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action != plan.ActionUpdate {
		return nil
	}

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

	var findings []RuleFinding

	// Check desired_count decrease.
	beforeCount := intFromJSONInterface(beforeMap["desired_count"])
	afterCount := intFromJSONInterface(afterMap["desired_count"])
	if beforeCount > 0 && afterCount >= 0 && afterCount < beforeCount {
		findings = append(findings, RuleFinding{
			Severity: SeverityMedium,
			Tags:     []string{"ops", "capacity"},
			Title:    fmt.Sprintf("ECS desired_count decreased on %s", rc.Address),
			Address:  rc.Address,
			Why: []string{
				fmt.Sprintf("desired_count: %d → %d", beforeCount, afterCount),
			},
			Recommendations: []string{
				"Verify capacity is sufficient for current load",
				"Consider scaling down gradually",
			},
		})
	}

	// Check deployment_minimum_healthy_percent decrease.
	beforeMinHealthy := getDeploymentConfigValue(beforeMap, "deployment_minimum_healthy_percent")
	afterMinHealthy := getDeploymentConfigValue(afterMap, "deployment_minimum_healthy_percent")
	if beforeMinHealthy > 0 && afterMinHealthy >= 0 && afterMinHealthy < beforeMinHealthy {
		findings = append(findings, RuleFinding{
			Severity: SeverityMedium,
			Tags:     []string{"ops"},
			Title:    fmt.Sprintf("ECS deployment_minimum_healthy_percent decreased on %s", rc.Address),
			Address:  rc.Address,
			Why: []string{
				fmt.Sprintf("deployment_minimum_healthy_percent: %d → %d", beforeMinHealthy, afterMinHealthy),
			},
			Recommendations: []string{
				"Lower minimum healthy percent increases risk of downtime during deployments",
				"Ensure health checks and rollback are configured",
			},
		})
	}

	return findings
}

func getDeploymentConfigValue(data map[string]interface{}, key string) int {
	// The field can be at top level or nested under deployment_configuration.
	if val, ok := data[key]; ok {
		return intFromJSONInterface(val)
	}
	if dc, ok := data["deployment_configuration"]; ok {
		if dcMap, ok := dc.(map[string]interface{}); ok {
			if val, ok := dcMap[key]; ok {
				return intFromJSONInterface(val)
			}
		}
	}
	return -1
}

func intFromJSONInterface(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	}
	return -1
}
