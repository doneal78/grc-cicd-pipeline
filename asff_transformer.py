import json
import boto3
import uuid
from datetime import datetime, timezone
from rich import print
from rich.panel import Panel

ACCOUNT_ID = "868832438584"
REGION = "us-east-1"
PRODUCT_ARN = f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default"

SEVERITY_MAP = {
    "HIGH": {"Label": "HIGH", "Normalized": 70},
    "MEDIUM": {"Label": "MEDIUM", "Normalized": 40},
    "LOW": {"Label": "LOW", "Normalized": 10},
}

SAMPLE_FINDING = {
    "filename": "asff_transformer.py",
    "test_id": "B105",
    "test_name": "hardcoded_password_string",
    "issue_text": "Possible hardcoded password: 'secret'",
    "issue_severity": "LOW",
    "issue_confidence": "MEDIUM",
    "line_number": 1
}


def load_bandit_report(path="gl-sast-report.json"):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[red]Bandit report not found at {path}[/red]")
        return None
    except json.JSONDecodeError as e:
        print(f"[red]Invalid JSON in report: {e}[/red]")
        return None


def bandit_to_asff(finding, repo_url="https://github.com/doneal78/grc-cicd-pipeline"):
    now = datetime.now(timezone.utc).isoformat()
    severity_label = finding.get("issue_severity", "MEDIUM").upper()
    severity = SEVERITY_MAP.get(severity_label, SEVERITY_MAP["MEDIUM"])

    finding_id = str(uuid.uuid4())
    filename = finding.get("filename", "unknown")
    line = finding.get("line_number", 0)
    test_id = finding.get("test_id", "UNKNOWN")
    test_name = finding.get("test_name", "Unknown Issue")
    issue_text = finding.get("issue_text", "")
    confidence = finding.get("issue_confidence", "MEDIUM")

    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{ACCOUNT_ID}/{REGION}/bandit/{finding_id}",
        "ProductArn": PRODUCT_ARN,
        "GeneratorId": f"bandit/{test_id}",
        "AwsAccountId": ACCOUNT_ID,
        "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": severity,
        "Title": f"[Bandit] {test_name} ({test_id})",
        "Description": issue_text[:1024],
        "SourceUrl": f"{repo_url}/blob/main/{filename}#L{line}",
        "Remediation": {
            "Recommendation": {
                "Text": f"Review {filename} line {line} for {test_name}. Confidence: {confidence}.",
                "Url": f"https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html"
            }
        },
        "Resources": [
            {
                "Type": "Other",
                "Id": f"{repo_url}/{filename}",
                "Details": {
                    "Other": {
                        "filename": filename,
                        "line_number": str(line),
                        "test_id": test_id,
                        "confidence": confidence,
                        "severity": severity_label
                    }
                }
            }
        ],
        "Compliance": {
            "Status": "FAILED"
        },
        "WorkflowState": "NEW",
        "RecordState": "ACTIVE"
    }


def import_to_security_hub(asff_findings):
    if not asff_findings:
        print("[yellow]No findings to import.[/yellow]")
        return 0, 0

    sh = boto3.client("securityhub", region_name=REGION)

    batch_size = 100
    total_imported = 0
    total_failed = 0

    for i in range(0, len(asff_findings), batch_size):
        batch = asff_findings[i:i + batch_size]
        try:
            response = sh.batch_import_findings(Findings=batch)
            imported = response.get("SuccessCount", 0)
            failed = response.get("FailedCount", 0)
            total_imported += imported
            total_failed += failed
            print(f"[green]Batch {i // batch_size + 1}: {imported} imported, {failed} failed[/green]")
        except Exception as e:
            print(f"[red]Error importing batch: {e}[/red]")
            total_failed += len(batch)

    return total_imported, total_failed


def run():
    print(Panel(
        "[bold cyan]GitLab SAST to Security Hub Importer[/bold cyan]\n"
        "[dim]Project 6 - OracleRecon GRC Engineering Portfolio[/dim]"
    ))

    report = load_bandit_report()
    results = report.get("results", []) if report else []

    if not results:
        print("[yellow]No real findings found. Using sample finding for demonstration.[/yellow]")
        results = [SAMPLE_FINDING]

    print(f"\n[bold]Processing {len(results)} findings[/bold]")

    asff_findings = [bandit_to_asff(f) for f in results]
    print(f"[green]Transformed {len(asff_findings)} findings to ASFF format[/green]")

    with open("asff_findings.json", "w") as f:
        json.dump(asff_findings, f, indent=2)
    print(f"[dim]ASFF findings saved to asff_findings.json[/dim]")

    print(f"\n[bold yellow]Importing to AWS Security Hub...[/bold yellow]")
    imported, failed = import_to_security_hub(asff_findings)

    print(f"\n[bold]Import complete: {imported} succeeded, {failed} failed[/bold]")


if __name__ == "__main__":
    run()
