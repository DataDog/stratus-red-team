# Issue draft template

Used for **suggested** new-technique issues. Never file without explicit user approval.

## Title pattern

`New attack technique: <Imperative verb> <object> <(platform qualifier if ambiguous)>`

### Good titles

1. `New attack technique: Azure SQL Server Firewall Rule Modification`
2. `New attack technique: Steal Azure Managed Identity Token via IMDS`
3. `New attack technique: Retrieve Azure App Service Publishing Credentials`

### Bad titles (do NOT file like this)

1. `Add SQL firewall rule technique` — missing `New attack technique:` prefix; vague verb.
2. `New attack technique: T1098.001` — title is a MITRE ID, not a human-readable action.
3. `Azure cred theft (seen in STORM-2949)` — campaign name belongs in the body; title doesn't describe the technique.

## Body template

The body must follow this exact section structure: `Context`, `How it works`, `Proposed technique` (with `Warm-up` and `Detonation`), `Relevant SDK functions`.

### SDK conventions per platform

Only reference SDKs already used in the Stratus codebase. Verify by running:
`find v2/internal/attacktechniques -name "*.go" | xargs grep -hE '^\s+"[^"]*"' | sort -u`

Cite the package + client method, e.g. `armsql.FirewallRulesClient.CreateOrUpdate`.

- **AWS** → `github.com/aws/aws-sdk-go-v2/service/<service>`. Services already imported: `bedrockruntime`, `cloudtrail`, `ec2`, `ec2instanceconnect`, `eks`, `iam`, `lambda`, `organizations`, `rds`, `rolesanywhere`, `route53resolver`, `s3`, `sagemaker`, `secretsmanager`, `ses`, `ssm`, `sts`. Pull a new service from `aws-sdk-go-v2` if needed (it's all under the same dependency).
- **Azure (control plane)** → `github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/<service>/arm<service>[/vN]`. Already imported: `armauthorization/v2`, `armcompute/v4`, `armkeyvault`, `armmsi`, `armnetwork/v6`, `armlocks`, `armstorage`. New `arm*` packages from the same SDK are fine.
- **Azure (data plane)** → already imported: `azblob` and sub-packages (`blob`, `container`, `sas`) under `github.com/Azure/azure-sdk-for-go/sdk/storage/azblob`; `azkeys` under `github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys`. Use the matching data-plane SDK for the service.
- **Entra ID** → `github.com/microsoftgraph/msgraph-sdk-go-core` + `github.com/microsoftgraph/msgraph-sdk-go/models`. Method form: `graphClient.<Resource>().<Action>(ctx, body, opts)`, e.g. `graphClient.ServicePrincipals().ByServicePrincipalId(id).AddPassword().Post(ctx, nil, nil)`.
- **GCP** → `cloud.google.com/go/<service>/apiv1` (`compute/apiv1` is already imported) and `cloud.google.com/go/storage`. New `apiv1` services from the same dependency root are fine.
- **Kubernetes / EKS** → `k8s.io/client-go/kubernetes` + `k8s.io/apimachinery` for cluster-internal actions. EKS control-plane actions go through `aws-sdk-go-v2/service/eks`.

If a TTP genuinely needs an SDK not on this list (e.g. an Azure service with no existing `arm*` import, or a non-Go SDK), flag it explicitly at the bottom of the issue body so the maintainer can decide whether to add the dependency. Do **not** silently pick an unrelated SDK.

For each SDK function, also include the underlying audit-log event name to monitor: ARM operation name (Azure), CloudTrail event name (AWS), audit log methodName (GCP), or Graph endpoint path (Entra ID).

### Worked example (issue #868)

Title: `New attack technique: Azure SQL Server Firewall Rule Modification`. Labels: `kind/new-technique`, `platform/azure`, `priority/seen-in-the-wild`.

```markdown
## Context

Seen in the wild in the STORM-2949 incident ([Microsoft Security Blog, May 2026](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/)).

## How it works

After compromising Azure credentials, the attacker modifies SQL server firewall rules to allow inbound access from attacker-controlled IP addresses, queries or exfiltrates data, then deletes the firewall rules to cover their tracks.

## Proposed technique

**Warm-up:**
- Create an Azure SQL server and database

**Detonation:**
- Add a firewall rule allowing access from an external IP
- (Optionally connect and exfiltrate data)
- Delete the firewall rule to simulate post-exfiltration cleanup

## Relevant SDK functions

Azure SDK for Go (`github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql`):
- `armsql.FirewallRulesClient.CreateOrUpdate` — add firewall rule
- `armsql.FirewallRulesClient.Delete` — remove firewall rule

ARM operation names to monitor: `microsoft.sql/servers/firewallrules/write`, `microsoft.sql/servers/firewallrules/delete`
```

### Body anti-patterns

1. No source link in `Context` — the issue is unreproducible.
2. Detonation lists 10+ steps — Stratus techniques are atomic. Split into multiple issues.
3. Vague SDK reference ("uses the Azure SDK") instead of the concrete package + method.
4. Citing only the raw HTTP/ARM endpoint and skipping the SDK function name — Stratus is implemented in Go against the official SDKs.

## Label rules

Pick only from the verified label list. Never invent labels.

- Always: `kind/new-technique`
- Exactly one platform: `platform/aws`, `platform/azure`, `platform/gcp`, `platform/entra-id`, `platform/eks`, `platform/k8s`
- Add `priority/seen-in-the-wild` if the source describes a real campaign or actor.

## Creating issues

Use `gh issue create --repo DataDog/stratus-red-team` with `--label` flags and a HEREDOC `--body` to preserve markdown. Print the returned URL after each creation.
