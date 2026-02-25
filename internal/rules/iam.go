package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/djeeteg007/tf-why/internal/plan"
)

var iamTypes = map[string]bool{
	"aws_iam_policy":                    true,
	"aws_iam_role_policy":               true,
	"aws_iam_user_policy":               true,
	"aws_s3_bucket_policy":              true,
	"aws_s3_bucket_public_access_block": true,
}

// IAMPolicyRule detects dangerous IAM and bucket policy changes.
type IAMPolicyRule struct{}

func (r *IAMPolicyRule) Evaluate(rc plan.ResourceChange) []RuleFinding {
	if !iamTypes[rc.Type] {
		return nil
	}

	action := rc.Change.Actions.ActionType()
	if action == plan.ActionNoop || action == plan.ActionRead {
		return nil
	}

	var findings []RuleFinding

	// Parse the after state to check for dangerous patterns.
	afterData := getAfterState(rc)
	if afterData == nil {
		return nil
	}

	// Check for policy document (could be in "policy" or "document" field).
	policyJSON := extractPolicyJSON(afterData)
	if policyJSON != "" {
		policyFindings := analyzePolicyDocument(policyJSON, rc.Address)
		findings = append(findings, policyFindings...)
	}

	// For s3_bucket_public_access_block, check if protections are being removed.
	if rc.Type == "aws_s3_bucket_public_access_block" {
		findings = append(findings, checkPublicAccessBlock(afterData, rc)...)
	}

	return findings
}

func getAfterState(rc plan.ResourceChange) map[string]interface{} {
	raw := rc.Change.After
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

func extractPolicyJSON(data map[string]interface{}) string {
	// Try "policy" field first, then "document".
	for _, key := range []string{"policy", "document"} {
		if val, ok := data[key]; ok {
			switch v := val.(type) {
			case string:
				return v
			}
		}
	}
	return ""
}

type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Principal interface{} `json:"Principal"`
}

func analyzePolicyDocument(policyJSON string, address string) []RuleFinding {
	var doc policyDocument
	if err := json.Unmarshal([]byte(policyJSON), &doc); err != nil {
		return nil
	}

	var findings []RuleFinding

	for i, stmt := range doc.Statement {
		actions := toStringSlice(stmt.Action)
		resources := toStringSlice(stmt.Resource)

		// Check for wildcard actions.
		for _, a := range actions {
			if a == "*" {
				findings = append(findings, RuleFinding{
					Severity: SeverityHigh,
					Tags:     []string{"security"},
					Title:    fmt.Sprintf("Wildcard Action \"*\" in IAM policy on %s", address),
					Address:  address,
					Why: []string{
						fmt.Sprintf("Statement[%d].Action includes \"*\" (allows all API actions)", i),
					},
					Recommendations: []string{
						"Restrict Action to specific API calls following least-privilege",
						"Use IAM Access Analyzer to scope down permissions",
					},
				})
			} else if strings.HasSuffix(a, ":*") {
				findings = append(findings, RuleFinding{
					Severity: SeverityHigh,
					Tags:     []string{"security"},
					Title:    fmt.Sprintf("Wildcard service Action %q in IAM policy on %s", a, address),
					Address:  address,
					Why: []string{
						fmt.Sprintf("Statement[%d].Action includes %q (allows all actions for service)", i, a),
					},
					Recommendations: []string{
						"Restrict Action to specific API calls following least-privilege",
					},
				})
			}

			// Check for dangerous actions.
			lower := strings.ToLower(a)
			if lower == "iam:passrole" || lower == "sts:assumerole" {
				findings = append(findings, RuleFinding{
					Severity: SeverityHigh,
					Tags:     []string{"security"},
					Title:    fmt.Sprintf("Dangerous action %q in IAM policy on %s", a, address),
					Address:  address,
					Why: []string{
						fmt.Sprintf("Statement[%d].Action includes %q (privilege escalation risk)", i, a),
					},
					Recommendations: []string{
						"Restrict Resource to specific role/user ARNs",
						"Add conditions to limit scope",
					},
				})
			}
		}

		// Check for wildcard resources.
		for _, res := range resources {
			if res == "*" {
				findings = append(findings, RuleFinding{
					Severity: SeverityHigh,
					Tags:     []string{"security"},
					Title:    fmt.Sprintf("Wildcard Resource \"*\" in IAM policy on %s", address),
					Address:  address,
					Why: []string{
						fmt.Sprintf("Statement[%d].Resource is \"*\" (applies to all resources)", i),
					},
					Recommendations: []string{
						"Restrict Resource to specific ARNs",
					},
				})
			}
		}
	}

	return deduplicateFindings(findings)
}

func checkPublicAccessBlock(afterData map[string]interface{}, rc plan.ResourceChange) []RuleFinding {
	fields := []string{
		"block_public_acls",
		"block_public_policy",
		"ignore_public_acls",
		"restrict_public_buckets",
	}

	var whys []string
	for _, f := range fields {
		if val, ok := afterData[f]; ok {
			if b, isBool := val.(bool); isBool && !b {
				whys = append(whys, fmt.Sprintf("%s is false (public access not blocked)", f))
			}
		}
	}

	if len(whys) == 0 {
		return nil
	}

	return []RuleFinding{{
		Severity: SeverityHigh,
		Tags:     []string{"security"},
		Title:    fmt.Sprintf("S3 public access protections weakened on %s", rc.Address),
		Address:  rc.Address,
		Why:      whys,
		Recommendations: []string{
			"Ensure all block_public_* and restrict_public_buckets are true",
			"Review bucket policy for unintended public access",
		},
	}}
}

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

// deduplicateFindings removes findings with identical title+address.
func deduplicateFindings(findings []RuleFinding) []RuleFinding {
	seen := make(map[string]bool)
	var result []RuleFinding
	for _, f := range findings {
		key := f.Title + "|" + f.Address
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}
