package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/djeeteg007/tf-why/internal/analysis"
	"github.com/djeeteg007/tf-why/internal/plan"
	"github.com/djeeteg007/tf-why/internal/render"
)

var version = "dev"

func main() {
	planFile := flag.String("plan", "", "Path to Terraform plan JSON file (default: read from stdin)")
	run := flag.Bool("run", false, "Run terraform plan + show automatically and analyze the result")
	tfDir := flag.String("dir", "", "Terraform working directory (used with --run)")
	format := flag.String("format", "text", "Output format: text or json")
	ci := flag.Bool("ci", false, "CI mode: set exit codes based on severity threshold")
	failOn := flag.String("fail-on", "high", "Severity threshold for non-zero exit in CI mode: low, medium, or high")
	only := flag.String("only", "", "Comma-separated resource types to include (e.g., aws_db_instance,aws_ecs_service)")
	excludeTag := flag.String("exclude-tag", "", "Comma-separated tags to exclude (e.g., security,cost)")
	maxFindings := flag.Int("max-findings", 20, "Maximum number of findings to report")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "tf-why — Explain Terraform plan changes with risk scoring\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  tf-why --run [flags]                          # run terraform plan automatically\n")
		fmt.Fprintf(os.Stderr, "  terraform show -json tfplan | tf-why [flags]  # pipe plan JSON via stdin\n")
		fmt.Fprintf(os.Stderr, "  tf-why --plan plan.json [flags]               # read plan JSON from file\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nCI Exit Codes:\n")
		fmt.Fprintf(os.Stderr, "  0   — severity below threshold (or no findings)\n")
		fmt.Fprintf(os.Stderr, "  10  — medium severity threshold reached\n")
		fmt.Fprintf(os.Stderr, "  20  — high severity threshold reached\n")
		fmt.Fprintf(os.Stderr, "  1   — error (invalid input, flags, etc.)\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("tf-why %s\n", version)
		os.Exit(0)
	}

	// Disable color if requested, if NO_COLOR env is set, or if stdout is not a terminal.
	if *noColor || os.Getenv("NO_COLOR") != "" {
		render.ColorEnabled = false
	} else if fi, err := os.Stdout.Stat(); err == nil {
		if fi.Mode()&os.ModeCharDevice == 0 {
			render.ColorEnabled = false
		}
	}

	// Open input.
	var input io.Reader
	if *run {
		r, err := runTerraformPlan(*tfDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		input = r
	} else if *planFile != "" {
		f, err := os.Open(*planFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot open plan file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		input = f
	} else {
		input = os.Stdin
	}

	// Parse plan.
	p, err := plan.Parse(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Build options.
	opts := analysis.Options{
		MaxFindings: *maxFindings,
	}
	if *only != "" {
		opts.OnlyTypes = splitCSV(*only)
	}
	if *excludeTag != "" {
		opts.ExcludeTags = splitCSV(*excludeTag)
	}

	// Analyze.
	result := analysis.Analyze(p, opts)

	// Render output.
	switch *format {
	case "json":
		if err := render.JSON(os.Stdout, result); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "text":
		render.Text(os.Stdout, result)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format %q (use 'text' or 'json')\n", *format)
		os.Exit(1)
	}

	// CI exit codes.
	if *ci {
		threshold := analysis.ParseSeverity(*failOn)
		if result.OverallSeverity >= threshold {
			switch result.OverallSeverity {
			case analysis.SeverityMedium:
				os.Exit(10)
			case analysis.SeverityHigh:
				os.Exit(20)
			default:
				os.Exit(10)
			}
		}
		os.Exit(0)
	}
}

// runTerraformPlan executes `terraform plan` and `terraform show -json`
// and returns a reader with the JSON plan output.
func runTerraformPlan(dir string) (io.Reader, error) {
	tfBin, err := exec.LookPath("terraform")
	if err != nil {
		return nil, fmt.Errorf("terraform not found in PATH: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "tf-why-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}

	planPath := filepath.Join(tmpDir, "tfplan")

	// Determine working directory.
	workDir := dir
	if workDir == "" {
		workDir, _ = os.Getwd()
	}

	// Step 1: terraform plan -out=<tmpfile>
	fmt.Fprintf(os.Stderr, "Running: terraform plan ...\n")
	planCmd := exec.Command(tfBin, "plan", "-out="+planPath)
	planCmd.Dir = workDir
	planCmd.Stdout = os.Stderr // show terraform output on stderr
	planCmd.Stderr = os.Stderr
	if err := planCmd.Run(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("terraform plan failed: %w", err)
	}

	// Step 2: terraform show -json <planfile>
	fmt.Fprintf(os.Stderr, "Running: terraform show -json ...\n")
	showCmd := exec.Command(tfBin, "show", "-json", planPath)
	showCmd.Dir = workDir
	showCmd.Stderr = os.Stderr
	jsonOut, err := showCmd.Output()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("terraform show failed: %w", err)
	}

	// Cleanup temp plan file.
	_ = os.RemoveAll(tmpDir)

	return strings.NewReader(string(jsonOut)), nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
