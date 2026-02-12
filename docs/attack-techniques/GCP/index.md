# GCP

This page contains the Stratus attack techniques for GCP, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.


## Initial Access
  
  - [Steal and Use the GCE Default Service Account Token from Outside Google Cloud](./gcp.initial-access.use-compute-sa-outside-gcp.md)
  

## Persistence
  
  - [Register SSH public key to instance metadata](./gcp.lateral-movement.add-sshkey-instance-metadata.md)
  
  - [Backdoor a GCP Service Account through its IAM Policy](./gcp.persistence.backdoor-service-account-policy.md)
  
  - [Create an Admin GCP Service Account](./gcp.persistence.create-admin-service-account.md)
  
  - [Create a GCP Service Account Key](./gcp.persistence.create-service-account-key.md)
  
  - [Invite an External User to a GCP Project](./gcp.persistence.invite-external-user.md)
  

## Privilege Escalation
  
  - [Create an Admin GCP Service Account](./gcp.persistence.create-admin-service-account.md)
  
  - [Create a GCP Service Account Key](./gcp.persistence.create-service-account-key.md)
  
  - [Impersonate GCP Service Accounts](./gcp.privilege-escalation.impersonate-service-accounts.md)
  

## Credential Access
  
  - [Retrieve a High Number of Secret Manager secrets](./gcp.credential-access.secretmanager-retrieve-secrets.md)
  
  - [Steal and Use the GCE Default Service Account Token from Outside Google Cloud](./gcp.initial-access.use-compute-sa-outside-gcp.md)
  

## Discovery
  
  - [Enumerate Permissions of a GCP Service Account](./gcp.discovery.enumerate-permissions.md)
  

## Lateral Movement
  
  - [Register SSH public key to instance metadata](./gcp.lateral-movement.add-sshkey-instance-metadata.md)
  

## Exfiltration
  
  - [Exfiltrate Compute Disk by sharing it](./gcp.exfiltration.share-compute-disk.md)
  
  - [Exfiltrate Compute Image by sharing it](./gcp.exfiltration.share-compute-image.md)
  
  - [Exfiltrate Compute Disk by sharing a snapshot](./gcp.exfiltration.share-compute-snapshot.md)
  

## Impact
  
  - [Create a GCE GPU Virtual Machine](./gcp.impact.create-gpu-vm.md)
  
  - [Create GCE Instances in Multiple Zones](./gcp.impact.create-instances-in-multiple-zones.md)
  
