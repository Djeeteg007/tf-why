# tf-why

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)

**Explain Terraform plan changes in human language with risk scoring.**

No LLM, no external calls, no API keys — pure deterministic rules applied to `terraform show -json` output. Open source under the MIT license.

```
$ tf-why --run

Plan Summary: 0 to create, 1 to update, 0 to delete, 1 to replace
Overall Severity: HIGH

2 finding(s):

─── 1. [HIGH] Database aws_db_instance.main will be replaced — potential data loss ───
  Resource: aws_db_instance.main
  Tags:     downtime, data
  Why:
    - engine_version: "11.9" → "16.1"
    - replace triggered by: engine_version
  Recommendations:
    [ ] Take a snapshot before applying
    [ ] Confirm rollback plan; expect downtime
    [ ] Verify data migration strategy
```

## Install

### Homebrew (macOS / Linux)

```bash
brew tap djeeteg007/tf-why
brew install tf-why
```

### From source

```bash
go install github.com/djeeteg007/tf-why/cmd/tf-why@latest
```

### Build locally

```bash
git clone https://github.com/djeeteg007/tf-why.git
cd tf-why
make build
```

## Quick start

```bash
# Easiest — run terraform plan automatically:
tf-why --run

# Or in a different Terraform directory:
tf-why --run --dir ./infra/production

# Pipe from terraform manually:
terraform plan -out=tfplan
terraform show -json tfplan | tf-why

# Read from a saved plan JSON file:
tf-why --plan plan.json
```

## Usage

```bash
# Human-readable output (default)
tf-why --run

# JSON output for scripting / jq
tf-why --run --format json

# CI mode — non-zero exit code when severity threshold is reached
tf-why --run --ci --fail-on high

# Filter to specific resource types
tf-why --run --only aws_db_instance,aws_ecs_service

# Exclude findings by tag
tf-why --run --exclude-tag cost,security

# Limit number of findings
tf-why --run --max-findings 5

# Combine flags
tf-why --plan plan.json --ci --fail-on medium --format json --max-findings 10
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--run` | `false` | Run `terraform plan` + `terraform show -json` automatically |
| `--dir <path>` | current dir | Terraform working directory (used with `--run`) |
| `--plan <file>` | stdin | Path to Terraform plan JSON file |
| `--format <text\|json>` | `text` | Output format |
| `--ci` | `false` | Enable CI mode with exit codes |
| `--fail-on <low\|medium\|high>` | `high` | Severity threshold for CI exit codes |
| `--only <types>` | (all) | Comma-separated resource types to include |
| `--exclude-tag <tags>` | (none) | Comma-separated tags to exclude |
| `--max-findings <n>` | `20` | Maximum findings to report |
| `--version` | | Print version and exit |

## CI/CD integration

When `--ci` is set, tf-why uses deterministic exit codes:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Overall severity is below the `--fail-on` threshold, or no findings |
| `1` | Error (invalid input, bad flags, terraform not found, etc.) |
| `10` | Medium severity threshold reached |
| `20` | High severity threshold reached |

### GitHub Actions

```yaml
steps:
  - name: Terraform plan
    run: terraform plan -out=tfplan

  - name: Analyze plan risks
    run: terraform show -json tfplan | tf-why --ci --fail-on high
```

Or using `--run`:

```yaml
steps:
  - name: Analyze plan risks
    run: tf-why --run --ci --fail-on high
```

### GitLab CI

```yaml
plan:analyze:
  script:
    - tf-why --run --ci --fail-on medium --format json
  allow_failure:
    exit_codes:
      - 10  # allow medium, block high
```

### Bitbucket Pipelines

```yaml
- step:
    name: Analyze Terraform plan
    script:
      - terraform plan -out=tfplan
      - terraform show -json tfplan | tf-why --ci --fail-on high
```

## What it detects

### Rules

| Rule | Resource Types | Severity | Tags |
|------|---------------|----------|------|
| Any replace (destroy+create) | All | HIGH | downtime |
| Any delete | All | HIGH | ops |
| Wildcard IAM Action (`*` or `service:*`) | `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`, `aws_s3_bucket_policy` | HIGH | security |
| Wildcard IAM Resource (`*`) | Same as above | HIGH | security |
| `iam:PassRole` or `sts:AssumeRole` added | Same as above | HIGH | security |
| S3 public access block weakened | `aws_s3_bucket_public_access_block` | HIGH | security |
| Security group open to internet on dangerous ports (22, 3389, 5432, 3306, 9200, 6379) | `aws_security_group`, `aws_security_group_rule` | HIGH | security |
| RDS/Aurora replace | `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance` | HIGH | downtime, data |
| RDS major engine version upgrade | Same as above | HIGH | downtime |
| RDS minor engine version change | Same as above | MEDIUM | downtime |
| ECS desired_count decrease | `aws_ecs_service` | MEDIUM | ops, capacity |
| ECS deployment_minimum_healthy_percent decrease | `aws_ecs_service` | MEDIUM | ops |
| Networking resource replace/delete | `aws_route`, `aws_route_table`, `aws_network_acl`, `aws_lb_listener`, `aws_lb_listener_rule`, `aws_nat_gateway` | HIGH | network |
| Networking resource update | Same as above | MEDIUM | network |
| KMS key/alias replace or delete | `aws_kms_key`, `aws_kms_alias` | HIGH | security, ops |

### Tags

Findings are tagged for filtering with `--exclude-tag`:

| Tag | Description |
|-----|-------------|
| `security` | IAM, encryption, public access changes |
| `downtime` | Replace operations, database upgrades |
| `ops` | Deletes, scaling changes |
| `network` | Routing, load balancers, NAT gateways |
| `capacity` | Scale-down operations |
| `data` | Potential data loss (database replace) |

## Sensitive data handling

- Fields marked as sensitive in the Terraform plan are displayed as `<sensitive>` — actual values are never printed.
- Unknown values (computed after apply) are displayed as `<unknown>`.

## Project structure

```
cmd/tf-why/main.go              CLI entrypoint
internal/
  plan/parser.go                Terraform plan JSON decoder
  analysis/analyzer.go          Rule orchestration, filtering, sorting
  rules/
    rules.go                    Rule interface and registry
    generic.go                  Replace/delete catch-all
    iam.go                      IAM and S3 policy analysis
    security_group.go           Security group port analysis
    rds.go                      RDS/Aurora change analysis
    ecs.go                      ECS service scaling analysis
    networking.go               Network resource analysis
    kms.go                      KMS key/alias analysis
  render/
    text.go                     Human-readable output
    json.go                     Machine-readable JSON output
  util/
    diff.go                     Diff extraction and formatting
testdata/                       Test fixtures (plan JSON samples)
```

## Development

```bash
make build            # Build binary
make test             # Run all tests
make lint             # Run linter (requires golangci-lint)
make release-dry-run  # Test goreleaser config locally
```

### Creating a release

```bash
# Tag and push
git tag v0.1.0
git push origin v0.1.0

# Build release artifacts (requires goreleaser: brew install goreleaser)
goreleaser release --clean

# Update SHA256 hashes in homebrew-tf-why/Formula/tf-why.rb from checksums.txt
# Push the formula to your homebrew-tf-why tap repo
```

### Homebrew tap setup

To make `brew install tf-why` work, create a separate repo called `homebrew-tf-why` on GitHub (`github.com/djeeteg007/homebrew-tf-why`) and copy the formula:

```bash
# Create the tap repo
mkdir homebrew-tf-why
cp homebrew-tf-why/Formula/tf-why.rb homebrew-tf-why/
cd homebrew-tf-why
git init && git add -A && git commit -m "Add tf-why formula"
# Push to github.com/djeeteg007/homebrew-tf-why
```

After a release, update the SHA256 values in the formula from the `checksums.txt` release asset, then push.

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/djeeteg007/tf-why).

## License

This project is open source and available under the [MIT License](LICENSE).
