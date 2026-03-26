# GCP

This page contains the Stratus attack techniques for GCP, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.


## Initial Access
  
  - [Steal and Use the GCE Default Service Account Token from Outside Google Cloud](./gcp.initial-access.use-compute-sa-outside-gcp.md)
  

## Execution
  
  - [Grant IAP Tunnel Access to an External Identity](./gcp.execution.iap-tunnel-session.md)
  
  - [Modify a GCE Instance Startup Script](./gcp.execution.modify-gce-startup-script.md)
  
  - [Inject a Malicious Startup Script into a Vertex AI Workbench Instance](./gcp.execution.modify-vertex-notebook-startup.md)
  
  - [Execute Commands on GCE Instances via OS Config Agent](./gcp.execution.os-config-run-command.md)
  

## Persistence
  
  - [Register SSH public key to instance metadata](./gcp.lateral-movement.add-sshkey-instance-metadata.md)
  
  - [Backdoor a GCP Service Account through its IAM Policy](./gcp.persistence.backdoor-service-account-policy.md)
  
  - [Create an Admin GCP Service Account](./gcp.persistence.create-admin-service-account.md)
  
  - [Create a GCP Service Account Key](./gcp.persistence.create-service-account-key.md)
  
  - [Invite an External User to a GCP Project](./gcp.persistence.invite-external-user.md)
  

## Privilege Escalation
  
  - [Modify a GCE Instance Startup Script](./gcp.execution.modify-gce-startup-script.md)
  
  - [Create an Admin GCP Service Account](./gcp.persistence.create-admin-service-account.md)
  
  - [Create a GCP Service Account Key](./gcp.persistence.create-service-account-key.md)
  
  - [Impersonate GCP Service Accounts](./gcp.privilege-escalation.impersonate-service-accounts.md)
  
  - [Inject a Malicious Startup Script into a Vertex AI Workbench Instance](./gcp.execution.modify-vertex-notebook-startup.md)
  

## Defense Evasion
  
  - [Delete a Cloud DNS Logging Policy](./gcp.defense-evasion.delete-dns-logs.md)
  
  - [Disable Data Access Audit Logs for a GCP Service](./gcp.defense-evasion.disable-audit-logs.md)
  
  - [Attempt to Remove a GCP Project from its Organization](./gcp.defense-evasion.remove-project-from-organization.md)
  
  - [Disable VPC Flow Logs on a Subnet](./gcp.defense-evasion.remove-vpc-flow-logs.md)
  
  - [Delete a GCP Log Sink](./gcp.defense-evasion.delete-logging-sink.md)
  
  - [Disable a GCP Log Sink](./gcp.defense-evasion.disable-logging-sink.md)
  
  - [Reduce Log Retention Period on a Cloud Logging Sink Bucket](./gcp.defense-evasion.reduce-sink-log-retention.md)
  

## Credential Access
  
  - [Retrieve a High Number of Secret Manager secrets](./gcp.credential-access.secretmanager-retrieve-secrets.md)
  
  - [Steal and Use the GCE Default Service Account Token from Outside Google Cloud](./gcp.initial-access.use-compute-sa-outside-gcp.md)
  

## Discovery
  
  - [Read GCE Instance Metadata via the Compute API](./gcp.discovery.download-instance-metadata.md)
  
  - [Enumerate Permissions of a GCP Service Account](./gcp.discovery.enumerate-permissions.md)
  

## Lateral Movement
  
  - [Grant IAP Tunnel Access to an External Identity](./gcp.execution.iap-tunnel-session.md)
  
  - [Register SSH public key to instance metadata](./gcp.lateral-movement.add-sshkey-instance-metadata.md)
  

## Exfiltration
  
  - [Exfiltrate Compute Disk by sharing it](./gcp.exfiltration.share-compute-disk.md)
  
  - [Exfiltrate Compute Image by sharing it](./gcp.exfiltration.share-compute-image.md)
  
  - [Exfiltrate Compute Disk by sharing a snapshot](./gcp.exfiltration.share-compute-snapshot.md)
  

## Impact
  
  - [Create a GCE GPU Virtual Machine](./gcp.impact.create-gpu-vm.md)
  
  - [Create GCE Instances in Multiple Zones](./gcp.impact.create-instances-in-multiple-zones.md)
  
