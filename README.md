# GRC CI/CD Pipeline

A GitLab CI/CD pipeline configuration and Python transformer that takes SAST (Static Application Security Testing) findings from Bandit, converts them to Amazon Security Finding Format (ASFF), and imports them directly into AWS Security Hub. Application security evidence and infrastructure compliance evidence in one dashboard.

Part of the OracleRecon GRC Engineering Portfolio.

---

## What it does

Bandit scans Python source code for security vulnerabilities. The ASFF transformer reads the Bandit JSON report, maps each finding to the required Security Hub schema, and calls `batch_import_findings` to import them. The result: Bandit findings appear in the same Security Hub dashboard as the infrastructure compliance findings from FSBP and CIS standards.

For SOC 2 CC8.1 Change Management, this provides automated evidence that code is scanned for security issues as part of the development process.

---

## Pipeline stages

The `.gitlab-ci.yml` defines three stages.

`lint` — Runs flake8 for Python style and syntax validation. Allows failure so it does not block the pipeline on style issues.

`security` — Runs Bandit and saves output as `gl-sast-report.json`. Artifact preserved for 30 days and passed to the next stage.

`import-to-security-hub` — Runs `asff_transformer.py` to import findings to Security Hub. Runs only on the default branch.

---

## Files

`asff_transformer.py` — Reads the Bandit report, transforms each finding to ASFF format, and calls Security Hub batch_import_findings. Falls back to a sample finding for demonstration when no real findings exist.

`.gitlab-ci.yml` — Three-stage pipeline definition with artifact passing and branch filtering.

---

## ASFF transformation

Each Bandit finding maps to ASFF fields:

| Bandit field | ASFF field |
|---|---|
| test_id | GeneratorId (bandit/TEST_ID) |
| issue_severity | Severity.Label and Severity.Normalized |
| test_name | Title |
| issue_text | Description |
| filename + line_number | SourceUrl and Resources |
| issue_confidence | Remediation recommendation |

Finding IDs are generated with uuid.uuid4() to guarantee uniqueness across runs.

---

## Confirmed result

Transformer ran against the OracleRecon account. 1 finding imported, 0 failed. Verified in Security Hub via get_findings filtered by GeneratorId prefix bandit/: LOW severity, hardcoded_password_string B105, FAILED compliance status.

---

## Setup

Install dependencies:

```
pip install boto3 bandit
```

Run Bandit to generate the report:

```
bandit -r . --exclude ./.venv -f json -o gl-sast-report.json
```

Run the transformer to import findings to Security Hub:

```
python asff_transformer.py
```

AWS credentials must be configured with SecurityHub:BatchImportFindings permission.

---

## Portfolio note

This project uses Option 2 for portfolio demonstration: code lives on GitHub and the pipeline was run locally against the live OracleRecon account. The `.gitlab-ci.yml` documents exactly how the pipeline runs in a real GitLab environment. The Security Hub import was confirmed against a real account.

---

## New concepts introduced

**SAST** — Static Application Security Testing. Analyzes source code without running it. Bandit is Python-specific and checks for hardcoded passwords, dangerous function use, SQL injection patterns, and more.

**ASFF** — Amazon Security Finding Format. The standardized JSON schema Security Hub uses to accept findings from any source. SchemaVersion, ProductArn, GeneratorId, and Resources are all required fields.

**batch_import_findings** — Security Hub API that accepts up to 100 findings per call. Returns SuccessCount and FailedCount.

**uuid.uuid4()** — Generates a random version 4 UUID. Used to create unique finding IDs for each Security Hub submission.

---

## Related projects

Project 3 Terraform Baseline: https://github.com/doneal78/grc-terraform-baseline

The infrastructure compliance findings in Security Hub that this project joins come from the standards enabled in Project 3 and 4.

Full portfolio: https://github.com/doneal78
