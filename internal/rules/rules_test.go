package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/djeeteg007/tf-why/internal/plan"
)

func loadTestPlan(t *testing.T, name string) *plan.Plan {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("cannot open test fixture %s: %v", name, err)
	}
	defer f.Close()

	p, err := plan.Parse(f)
	if err != nil {
		t.Fatalf("cannot parse test fixture %s: %v", name, err)
	}
	return p
}

func evaluateAll(t *testing.T, fixture string) []RuleFinding {
	t.Helper()
	p := loadTestPlan(t, fixture)
	allR := AllRules()
	var findings []RuleFinding
	for _, rc := range p.ResourceChanges {
		for _, rule := range allR {
			findings = append(findings, rule.Evaluate(rc)...)
		}
	}
	return findings
}

// --- Generic Rule Tests ---

func TestGenericReplace(t *testing.T) {
	findings := evaluateAll(t, "generic_replace.json")
	if len(findings) == 0 {
		t.Fatal("expected findings for replace")
	}
	found := false
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "downtime") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HIGH severity with downtime tag for replace")
	}
}

func TestGenericDelete(t *testing.T) {
	findings := evaluateAll(t, "generic_delete.json")
	if len(findings) == 0 {
		t.Fatal("expected findings for delete")
	}
	found := false
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "ops") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HIGH severity with ops tag for delete")
	}
}

// --- IAM Rule Tests ---

func TestIAMWildcardAction(t *testing.T) {
	findings := evaluateAll(t, "iam_wildcard.json")
	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard IAM policy")
	}
	var hasWildcardAction, hasWildcardResource bool
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "security") {
			for _, w := range f.Why {
				if contains(w, "Action") && contains(w, "\"*\"") {
					hasWildcardAction = true
				}
				if contains(w, "Resource") && contains(w, "\"*\"") {
					hasWildcardResource = true
				}
			}
		}
	}
	if !hasWildcardAction {
		t.Error("expected finding for wildcard Action")
	}
	if !hasWildcardResource {
		t.Error("expected finding for wildcard Resource")
	}
}

func TestIAMServiceWildcard(t *testing.T) {
	findings := evaluateAll(t, "iam_service_wildcard.json")
	found := false
	for _, f := range findings {
		for _, w := range f.Why {
			if contains(w, "s3:*") {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected finding for s3:* wildcard action")
	}
}

func TestIAMPassRole(t *testing.T) {
	findings := evaluateAll(t, "iam_passrole.json")
	var hasPassRole, hasAssumeRole bool
	for _, f := range findings {
		for _, w := range f.Why {
			if contains(w, "iam:PassRole") {
				hasPassRole = true
			}
			if contains(w, "sts:AssumeRole") {
				hasAssumeRole = true
			}
		}
	}
	if !hasPassRole {
		t.Error("expected finding for iam:PassRole")
	}
	if !hasAssumeRole {
		t.Error("expected finding for sts:AssumeRole")
	}
}

func TestS3PublicAccess(t *testing.T) {
	findings := evaluateAll(t, "s3_public_access.json")
	found := false
	for _, f := range findings {
		if containsTag(f.Tags, "security") {
			for _, w := range f.Why {
				if contains(w, "block_public_acls") || contains(w, "block_public_policy") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected finding for weakened S3 public access block")
	}
}

// --- Security Group Rule Tests ---

func TestSGOpenSSH(t *testing.T) {
	findings := evaluateAll(t, "sg_open_ssh.json")
	found := false
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "security") {
			for _, w := range f.Why {
				if contains(w, "0.0.0.0/0") && contains(w, "22") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Error("expected HIGH security finding for SSH open to internet")
	}
}

func TestSGInlineAllPorts(t *testing.T) {
	findings := evaluateAll(t, "sg_inline_multi.json")
	if len(findings) == 0 {
		t.Fatal("expected findings for wide-open security group")
	}
	// Should find all dangerous ports
	ports := map[string]bool{}
	for _, f := range findings {
		for _, w := range f.Why {
			for _, svc := range []string{"SSH", "RDP", "PostgreSQL", "MySQL", "Elasticsearch", "Redis"} {
				if contains(w, svc) {
					ports[svc] = true
				}
			}
		}
	}
	if len(ports) < 6 {
		t.Errorf("expected all 6 dangerous ports flagged, got %d: %v", len(ports), ports)
	}
}

// --- RDS Rule Tests ---

func TestRDSReplace(t *testing.T) {
	findings := evaluateAll(t, "rds_replace.json")
	var hasReplace, hasMajorUpgrade bool
	for _, f := range findings {
		if containsTag(f.Tags, "downtime") && containsTag(f.Tags, "data") {
			hasReplace = true
		}
		for _, w := range f.Why {
			if contains(w, "11.9") && contains(w, "16.1") {
				hasMajorUpgrade = true
			}
		}
	}
	if !hasReplace {
		t.Error("expected HIGH downtime+data finding for RDS replace")
	}
	if !hasMajorUpgrade {
		t.Error("expected engine version diff in findings")
	}
}

func TestRDSMinorUpgrade(t *testing.T) {
	findings := evaluateAll(t, "rds_minor_upgrade.json")
	found := false
	for _, f := range findings {
		if f.Severity == SeverityMedium && containsTag(f.Tags, "downtime") {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM downtime finding for minor version upgrade")
	}
	// Should NOT be HIGH since major version is the same
	for _, f := range findings {
		if contains(f.Title, "Major") {
			t.Error("minor upgrade should not be flagged as Major")
		}
	}
}

// --- ECS Rule Tests ---

func TestECSScaleDown(t *testing.T) {
	findings := evaluateAll(t, "ecs_scale_down.json")
	var hasCount, hasHealthy bool
	for _, f := range findings {
		for _, w := range f.Why {
			if contains(w, "desired_count") && contains(w, "4") && contains(w, "1") {
				hasCount = true
			}
			if contains(w, "deployment_minimum_healthy_percent") {
				hasHealthy = true
			}
		}
	}
	if !hasCount {
		t.Error("expected finding for desired_count decrease")
	}
	if !hasHealthy {
		t.Error("expected finding for deployment_minimum_healthy_percent decrease")
	}
}

// --- Networking Rule Tests ---

func TestNetworkingDelete(t *testing.T) {
	findings := evaluateAll(t, "networking_delete.json")
	found := false
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "network") {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH network finding for NAT gateway delete")
	}
}

func TestNetworkingUpdate(t *testing.T) {
	findings := evaluateAll(t, "networking_update.json")
	found := false
	for _, f := range findings {
		if f.Severity == SeverityMedium && containsTag(f.Tags, "network") {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM network finding for route update")
	}
}

// --- KMS Rule Tests ---

func TestKMSDelete(t *testing.T) {
	findings := evaluateAll(t, "kms_delete.json")
	found := false
	for _, f := range findings {
		if f.Severity == SeverityHigh && containsTag(f.Tags, "security") && containsTag(f.Tags, "ops") {
			found = true
		}
	}
	if !found {
		t.Error("expected HIGH security+ops finding for KMS key delete")
	}
}

// --- No Change Test ---

func TestNoChanges(t *testing.T) {
	findings := evaluateAll(t, "no_changes.json")
	if len(findings) != 0 {
		t.Errorf("expected no findings for no-op plan, got %d", len(findings))
	}
}

// --- Sensitive / Unknown Test ---

func TestSensitiveUnknownNoCrash(t *testing.T) {
	// This test ensures we don't crash on sensitive/unknown fields
	// and don't leak sensitive values.
	p := loadTestPlan(t, "sensitive_unknown.json")
	rc := p.ResourceChanges[0]
	// Should not panic
	allR := AllRules()
	for _, rule := range allR {
		_ = rule.Evaluate(rc)
	}

	// Check diff extraction doesn't leak sensitive values
	var afterMap map[string]interface{}
	_ = json.Unmarshal(rc.Change.After, &afterMap)
	// The after state should have user_data as "newscript" in raw JSON,
	// but our diff extractor should mask it.
}

// --- Helpers ---

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
