package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "tf-why")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = filepath.Join("..", "..", "cmd", "tf-why")
	// Use the module root
	cmd.Dir = filepath.Join("..")
	// Actually build from the repo root
	rootDir, _ := filepath.Abs(filepath.Join("..", ".."))
	cmd.Dir = rootDir
	cmd.Args = []string{"go", "build", "-o", binPath, "./cmd/tf-why"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\n%s", err, out)
	}
	return binPath
}

func runBinary(t *testing.T, bin string, args []string, stdinFile string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)

	if stdinFile != "" {
		f, err := os.Open(stdinFile)
		if err != nil {
			t.Fatalf("cannot open stdin file: %v", err)
		}
		defer f.Close()
		cmd.Stdin = f
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("failed to run binary: %v\nstderr: %s", err, stderr.String())
	}

	return stdout.String() + stderr.String(), exitCode
}

func fixtureDir() string {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata"))
	return abs
}

func TestCLIVersion(t *testing.T) {
	bin := buildBinary(t)
	out, code := runBinary(t, bin, []string{"--version"}, "")
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "tf-why") {
		t.Errorf("expected version output containing 'tf-why', got %q", out)
	}
}

func TestCLIStdinText(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "iam_wildcard.json")
	out, code := runBinary(t, bin, nil, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "TERRAFORM PLAN ANALYSIS") {
		t.Errorf("expected TERRAFORM PLAN ANALYSIS in output, got:\n%s", out)
	}
	if !strings.Contains(out, "HIGH") {
		t.Errorf("expected HIGH severity in output, got:\n%s", out)
	}
}

func TestCLIPlanFlag(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "generic_replace.json")
	out, code := runBinary(t, bin, []string{"--plan", fixture}, "")
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "replace") {
		t.Errorf("expected 'replace' in output, got:\n%s", out)
	}
}

func TestCLIJSONFormat(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "iam_wildcard.json")
	out, code := runBinary(t, bin, []string{"--format", "json"}, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if _, ok := result["summary"]; !ok {
		t.Error("JSON output missing 'summary' field")
	}
	if _, ok := result["findings"]; !ok {
		t.Error("JSON output missing 'findings' field")
	}
}

func TestCLICIModeHighExit(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "iam_wildcard.json")
	_, code := runBinary(t, bin, []string{"--ci", "--fail-on", "high"}, fixture)
	if code != 20 {
		t.Errorf("expected exit 20 for HIGH severity with --fail-on high, got %d", code)
	}
}

func TestCLICIModeBelowThreshold(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "rds_minor_upgrade.json")
	_, code := runBinary(t, bin, []string{"--ci", "--fail-on", "high"}, fixture)
	if code != 0 {
		t.Errorf("expected exit 0 for MEDIUM severity with --fail-on high, got %d", code)
	}
}

func TestCLICIModeMediumExit(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "rds_minor_upgrade.json")
	_, code := runBinary(t, bin, []string{"--ci", "--fail-on", "medium"}, fixture)
	if code != 10 {
		t.Errorf("expected exit 10 for MEDIUM severity with --fail-on medium, got %d", code)
	}
}

func TestCLINoChanges(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "no_changes.json")
	out, code := runBinary(t, bin, nil, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected 'No findings' in output, got:\n%s", out)
	}
}

func TestCLIOnlyFilter(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "iam_wildcard.json")
	out, code := runBinary(t, bin, []string{"--only", "aws_s3_bucket"}, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("expected no findings with mismatched filter, got:\n%s", out)
	}
}

func TestCLIExcludeTag(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "generic_replace.json")
	out, code := runBinary(t, bin, []string{"--exclude-tag", "downtime"}, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if strings.Contains(out, "downtime") && !strings.Contains(out, "No findings") {
		// Check that no findings mention downtime tag
		if strings.Contains(out, "Tags:") && strings.Contains(out, "downtime") {
			t.Errorf("expected no downtime-tagged findings, got:\n%s", out)
		}
	}
}

func TestCLIMaxFindings(t *testing.T) {
	bin := buildBinary(t)
	fixture := filepath.Join(fixtureDir(), "sg_inline_multi.json")
	out, code := runBinary(t, bin, []string{"--format", "json", "--max-findings", "1"}, fixture)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	count := int(result["findings_count"].(float64))
	if count != 1 {
		t.Errorf("expected 1 finding with --max-findings 1, got %d", count)
	}
}
