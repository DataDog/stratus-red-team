---
name: test-attack-technique
description: Tests and validates Stratus Red Team attack techniques by executing warmup, detonation, and cleanup phases with comprehensive validation. Validates cloud credentials, parses command output, checks expected outcomes, and generates HTML reports. Use when testing attack techniques, validating TTPs, verifying technique behavior, or when user mentions stratus, warmup, detonate, or technique IDs like aws.*, azure.*, gcp.*, k8s.*, or entra-id.*. Supports AWS, Azure, GCP, Kubernetes, and Entra ID.
---

## Instructions

When this skill is invoked, follow this workflow:

### 1. Parse Input & Validate Technique Exists
- Extract the technique ID from arguments
- Check for `--skip-cleanup` flag
- **IMPORTANT**: Change to the `v2/` directory first: `cd v2`
- Run `go run cmd/stratus/*.go show <technique-id>` silently to verify the technique exists
- If it doesn't exist, show error and list available techniques with `go run cmd/stratus/*.go list`
- Store technique metadata (name, platform, MITRE ATT&CK tactic) for later use
- **Do not show verbose output** - just confirm it exists or error out

### 2. Validate Cloud Credentials
Based on the technique platform, validate current credentials and get explicit user confirmation.

See [references/credentials.md](references/credentials.md) for detailed validation commands per cloud provider.

**Quick reference:**
- **AWS**: Run `aws sts get-caller-identity` - show Account, UserId, Arn
- **Azure**: Run `az account show` - show name, id, user, tenantId. **CRITICAL**: Export `AZURE_SUBSCRIPTION_ID` and `ARM_SUBSCRIPTION_ID` environment variables before running stratus commands
- **GCP**: Run `gcloud config get-value project && gcloud auth list` - show project and active account
- **Kubernetes**: Run `kubectl config current-context && kubectl config view --minify` - show cluster and namespace
- **Entra ID**: Run `az ad signed-in-user show` - show userPrincipalName and id

**Present credentials to user and ask for explicit confirmation:**
```
Current credentials for <platform>:
<formatted credential info>

These credentials will be used to:
1. Create infrastructure (warmup)
2. Execute the attack technique (detonate)
3. Clean up resources (cleanup)

Do you want to proceed with these credentials?
```

Use AskUserQuestion to get confirmation. If user declines, stop and provide instructions for changing credentials.

### 3. Draft Expected Outcomes Plan
Based on the technique documentation, source code analysis, and your understanding of the attack:

**Read the technique details:**
- The output from `go run cmd/stratus/*.go show <technique-id>` provides the description
- **IMPORTANT**: Read the attack technique source code to understand the implementation intent and what resources are created. Look for:
  - Infrastructure creation logic (warmup phase)
  - Attack execution logic (detonation phase)
  - Resource names, types, and configurations
  - Expected outputs and artifacts
- Map the source code implementation to expected behaviors
- Understand the MITRE ATT&CK tactic and technique behavior

**Draft a high-level plan including:**

1. **Warmup Phase Expectations:**
   - Infrastructure to be created
   - Approximate resource count
   - Special configurations

2. **Detonation Phase Expectations:**
   - Actions to be performed
   - Artifacts generated (credentials, tokens, data)
   - Observable behaviors

3. **Validation Checks:**
   - What to verify after warmup
   - What to verify after detonation
   - **Note**: Focus only on resource creation, attack output, and artifacts - NOT audit logs or security monitoring

**Present the plan to the user:**

FIRST, output the complete plan as regular text (not in a tool call):
```
═══════════════════════════════════════════════════════════════
Test Execution Plan for <technique-name>
═══════════════════════════════════════════════════════════════

WARMUP PHASE - Expected Infrastructure:
• <list of expected resources>

DETONATION PHASE - Expected Attack Behavior:
• <list of expected actions and outcomes>

VALIDATION - What I'll Check:
• After warmup: <validation checks>
• After detonation: <validation checks>

═══════════════════════════════════════════════════════════════
```

THEN, after displaying the plan, use AskUserQuestion to get user validation:
- Option 1: "Yes, proceed with this plan"
- Option 2: "No, I want to modify the plan"

If the user wants to modify, discuss changes and update the plan before proceeding.

### 4. Execute Attack Lifecycle & Parse Output

Use TodoWrite to track progress through phases.

**Copy this checklist and track your progress:**
```
Test Execution Progress:
- [ ] Step 1: Validate technique exists
- [ ] Step 2: Validate and confirm credentials
- [ ] Step 3: Draft and approve execution plan
- [ ] Step 4: Export AZURE_SUBSCRIPTION_ID and ARM_SUBSCRIPTION_ID (Azure only)
- [ ] Step 5: Run warmup and parse output
- [ ] Step 6: Run detonation and parse output
- [ ] Step 7: Validate assumptions against results
- [ ] Step 8: Run cleanup (unless --skip-cleanup)
- [ ] Step 9: Generate HTML report
```

#### Warmup Phase

**For Azure techniques, first export the subscription IDs:**
```bash
export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export ARM_SUBSCRIPTION_ID=$AZURE_SUBSCRIPTION_ID
```

Then run warmup from the v2/ directory:
```bash
cd v2 && go run cmd/stratus/*.go warmup <technique-id>
```

**Parse the output to extract:**
- Resource identifiers (bucket names, instance IDs, ARNs)
- Status messages (success/failure)
- Warnings or errors

Store for validation. Output is unstructured - intelligently parse based on technique type (e.g., look for "Created S3 bucket stratus-red-team-xxx" patterns).

#### Detonation Phase
```bash
cd v2 && go run cmd/stratus/*.go detonate <technique-id>
```

**Parse the output to extract:**
- Attack execution messages
- Retrieved credentials, tokens, or exfiltrated data references
- Success/failure indicators
- Any error messages

#### Validation Phase
Compare expected vs. actual outcomes:
- Resources created match plan (use cloud provider CLI commands to verify when possible)
- Attack behaviors occurred as expected (validate using stratus output and cloud CLI commands)
- Document discrepancies
- **Important**: Validate using stratus output, cloud CLI commands, and direct resource checks - NOT audit logs or monitoring
- **Capture CLI commands and outputs**: For each validation check using CLI commands, store the command and its output for the report
- If CLI validation isn't feasible, suggest manual validation commands in the report

**Example validation approaches:**

*aws.credential-access.secretsmanager-retrieve-secrets:*
- Warmup: Secrets created in Secrets Manager
  - Run: `aws secretsmanager list-secrets` or `aws secretsmanager get-secret-value --secret-id <name>`
  - Capture: Command and output showing secrets exist
- Detonation: Secrets retrieved by attack
  - Check: Stratus logs only (no cloud environment changes)

*aws.impact.s3-ransomware-individual-deletion:*
- Warmup: S3 bucket with versioning enabled and files
  - Run: `aws s3 ls` and `aws s3 ls s3://<bucket-name>/`
  - Capture: Commands and outputs showing bucket and files
- Detonation: Bucket has only ransom note file remaining
  - Run: `aws s3 ls s3://<bucket-name>/`
  - Capture: Command and output showing only ransom note

Store results (including CLI commands and outputs) for report.

#### Cleanup Phase (runs by default)
```bash
cd v2 && go run cmd/stratus/*.go cleanup <technique-id>
```

Cleanup runs unless `--skip-cleanup` is set. Verify success and note any failures in report.

### 5. Generate HTML Report

Generate a comprehensive HTML report saved to the scratchpad directory with filename:
`test-report-<technique-id>-<timestamp>.html`

**Use the template file:** Read [assets/report-template.html](assets/report-template.html) and replace placeholders with actual values:

**Placeholders to replace:**
- `{{TECHNIQUE_ID}}`, `{{TECHNIQUE_NAME}}`, `{{PLATFORM}}`, `{{TACTIC}}`, `{{TIMESTAMP}}`, `{{CREDENTIAL_INFO}}`
- `{{EXPECTED_WARMUP_RESOURCES}}`, `{{EXPECTED_DETONATION_BEHAVIORS}}`, `{{PLANNED_CHECKS}}`
- `{{WARMUP_STATUS}}`, `{{WARMUP_STATUS_CLASS}}` (success/failure), `{{WARMUP_RESOURCES}}`, `{{WARMUP_OUTPUT}}`
- `{{DETONATION_STATUS}}`, `{{DETONATION_STATUS_CLASS}}`, `{{DETONATION_BEHAVIORS}}`, `{{DETONATION_OUTPUT}}`
- `{{VALIDATION_CHECKS}}` - Generate HTML for each check including CLI commands and outputs:
  ```html
  <div class="check pass">
      <strong>Check:</strong> Storage account exists
      <br><strong>Expected:</strong> stratus-rg-xxxxx created
      <br><strong>Actual:</strong> stratus-rg-xxxxx found in output
      <div class="check-command">$ aws s3 ls</div>
      <div class="check-output">2024-01-15 10:30:45 stratus-red-team-bucket-abc123</div>
      <strong>Status:</strong> Pass
  </div>
  ```
  Include CLI commands and outputs when validation involved running commands.
- `{{CLEANUP_STATUS}}`, `{{CLEANUP_STATUS_CLASS}}`, `{{CLEANUP_OUTPUT}}`
- `{{OVERALL_RESULT}}`, `{{CHECKS_PASSED}}`, `{{TOTAL_CHECKS}}`, `{{ISSUES}}`, `{{RECOMMENDATIONS}}`

After generation: show file path, display summary, suggest opening in browser.

### 6. Best Practices
- Use TodoWrite to track phase progress
- Set appropriate timeouts (cloud ops take minutes)
- Preserve all command output for report
- Intelligently parse unstructured output for identifiers, ARNs, names, IDs
- If parsing fails, include raw output and note manual verification needed
- Provide clear feedback at each step
- Always generate report, even on failures

## Requirements
- Go 1.22+
- Run from `v2/` directory
- Cloud credentials configured for target platform
- Permissions to create/delete resources
- Test/development environment only (not production)

## Safety
- Executes real attacks, creates cloud resources
- Run in dedicated test environment only
- May incur minimal costs
- Cleanup runs by default (use --skip-cleanup to preserve)
- May trigger security alerts (expected)
- Reports contain account IDs only, never credentials

## See Also
- [references/credentials.md](references/credentials.md) - Detailed credential validation for each cloud provider
