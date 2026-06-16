# Coverage matching heuristics

First match wins. Apply the checks in order.

## 1. Covered

An existing Stratus technique implements the **same action on the same cloud service on the same platform**.

- Same platform (aws / azure / gcp / entra-id / k8s / eks) AND
- Same cloud service or resource (Key Vault, S3, Storage account, IAM, etc.) AND
- Same action verb family (read/list, modify, delete, share, exfiltrate-via-SAS, …) AND
- **The Go implementation actually performs the same operation.** Read `v2/internal/attacktechniques/<platform>/<tactic>/<name>/main.go` and confirm the SDK calls map to the TTP. If the doc describes the right thing but the code does something narrower (e.g. only handles one resource subtype), downgrade to **Partial** or **Not covered** as appropriate.

MITRE ATT&CK ID alone is **never** sufficient — the description text, technique ID, *and* the Go code must align. Cite the full technique ID, e.g. `azure.exfiltration.storage-sas-export`.

## 2. Partial

**Same platform**, same service, but a meaningfully different sub-action or resource. Rare — only use when there's a clear, defensible adjacency.

Cross-cloud is **not** Partial — see below.

## 3. Open issue

No implementation exists, but an open GitHub issue with the `kind/new-technique` label covers it. Match on title keyword overlap + label. Cite the issue number (e.g. `#486`).

## 4. Not covered

None of the above. **This includes the case where an equivalent technique exists on a different cloud** — that does *not* count as coverage.

If a different-cloud equivalent does exist, surface it in the report's **Other platforms** column for context, but the status remains **Not covered**.

## Cross-cloud rule (important)

If Stratus covers *"dump contents of an S3 bucket"* (AWS) and the TTP is *"dump contents of an Azure Blob container"*, the status is **Not covered** — the platforms are different and the implementation work is different. Record the AWS technique ID in the **Other platforms** column so the reader sees that the concept exists elsewhere, then suggest a new issue for the Azure variant.

## Tie-breakers

- If multiple Stratus techniques on the same platform could match, pick the one whose ID best matches the action verb; list runners-up in the justification.
- If both a same-platform open issue and a different-platform implementation exist, status is **Open issue** (cite the issue); the different-platform one still goes in **Other platforms**.

## Good matches

1. TTP: *"Generated a SAS URL to download blobs from Azure Storage"* → **Covered**: `azure.exfiltration.storage-sas-export`. Same platform, same service, same verb.
2. TTP: *"Deployed VMAccess extension to create a new local admin"* → **Open issue**: `#486`.
3. TTP: *"Executed a PowerShell script via Azure Run Command"* → **Covered**: `azure.execution.vm-run-command`.
4. TTP: *"Requested managed identity token from Azure VM IMDS"* → **Not covered**. AWS equivalent `aws.credential-access.ec2-steal-instance-credentials` goes in the **Other platforms** column. Suggest a new Azure issue.
5. TTP: *"Dumped contents of an Azure Blob container"* → **Not covered**. AWS equivalents like `aws.exfiltration.s3-backdoor-bucket-policy` go in **Other platforms**. Different cloud is not coverage.

## Bad matches (do NOT make these)

1. ❌ TTP: *"Dumped contents of an Azure Blob container"* → classifying as **Partial** because `aws.exfiltration.s3-backdoor-bucket-policy` covers the AWS equivalent.
   Wrong: cross-cloud is **Not covered**, even when the concept is identical. The AWS technique goes in **Other platforms**, not in Status.

2. ❌ TTP: *"Requested managed identity token from Azure VM IMDS"* → classifying as **Partial** because `aws.credential-access.ec2-steal-instance-credentials` is the AWS twin.
   Wrong: same reason — cross-cloud is **Not covered**. List the AWS technique in **Other platforms**.

3. ❌ TTP: *"Mass downloaded files from OneDrive / SharePoint"* → classifying as **Covered** because `azure.exfiltration.storage-sas-export` is also "exfiltration".
   Wrong: different surface entirely (M365 SaaS ≠ Azure Storage control plane). Correct call: **Not covered**.

4. ❌ TTP: *"Modified Azure SQL firewall rules"* → classifying as **Partial** because issue `#130` covers Azure NSG ingress.
   Wrong: different service (NSG ≠ SQL firewall). Correct call: **Not covered** (or **Open issue** if a closer-matching issue exists).

5. ❌ TTP: *"Modified Key Vault access policies and read secrets"* → classifying as **Covered** because both fall under MITRE `T1484`.
   Wrong: MITRE tactic alone is insufficient. Correct call: **Not covered**.
