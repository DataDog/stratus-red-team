---
hide:
  - toc
---

# List of all Attack Techniques

This page contains the list of all Stratus Attack Techniques.

| Name   | Platform | MITRE ATT&CK Tactics |
| :----: | :------: | :------------------: |
| [Retrieve EC2 Password Data](./AWS/aws.credential-access.ec2-get-password-data.md) | [AWS](./AWS/index.md) | Credential Access |
| [Steal EC2 Instance Credentials](./AWS/aws.credential-access.ec2-steal-instance-credentials.md) | [AWS](./AWS/index.md) | Credential Access |
| [Retrieve a High Number of Secrets Manager secrets (Batch)](./AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets.md) | [AWS](./AWS/index.md) | Credential Access |
| [Retrieve a High Number of Secrets Manager secrets](./AWS/aws.credential-access.secretsmanager-retrieve-secrets.md) | [AWS](./AWS/index.md) | Credential Access |
| [Retrieve And Decrypt SSM Parameters](./AWS/aws.credential-access.ssm-retrieve-securestring-parameters.md) | [AWS](./AWS/index.md) | Credential Access |
| [Delete CloudTrail Trail](./AWS/aws.defense-evasion.cloudtrail-delete.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Disable CloudTrail Logging Through Event Selectors](./AWS/aws.defense-evasion.cloudtrail-event-selectors.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [CloudTrail Logs Impairment Through S3 Lifecycle Rule](./AWS/aws.defense-evasion.cloudtrail-lifecycle-rule.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Stop CloudTrail Trail](./AWS/aws.defense-evasion.cloudtrail-stop.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Delete DNS query logs](./AWS/aws.defense-evasion.dns-delete-logs.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Attempt to Leave the AWS Organization](./AWS/aws.defense-evasion.organizations-leave.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Remove VPC Flow Logs](./AWS/aws.defense-evasion.vpc-remove-flow-logs.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Execute Discovery Commands on an EC2 Instance](./AWS/aws.discovery.ec2-enumerate-from-instance.md) | [AWS](./AWS/index.md) | Discovery |
| [Download EC2 Instance User Data](./AWS/aws.discovery.ec2-download-user-data.md) | [AWS](./AWS/index.md) | Discovery |
| [Enumerate SES](./AWS/aws.discovery.ses-enumerate.md) | [AWS](./AWS/index.md) | Discovery |
| [Launch Unusual EC2 instances](./AWS/aws.execution.ec2-launch-unusual-instances.md) | [AWS](./AWS/index.md) | Execution |
| [Execute Commands on EC2 Instance via User Data](./AWS/aws.execution.ec2-user-data.md) | [AWS](./AWS/index.md) | Execution, Privilege Escalation |
| [Usage of ssm:SendCommand on multiple instances](./AWS/aws.execution.ssm-send-command.md) | [AWS](./AWS/index.md) | Execution |
| [Usage of ssm:StartSession on multiple instances](./AWS/aws.execution.ssm-start-session.md) | [AWS](./AWS/index.md) | Execution |
| [Open Ingress Port 22 on a Security Group](./AWS/aws.exfiltration.ec2-security-group-open-port-22-ingress.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate an AMI by Sharing It](./AWS/aws.exfiltration.ec2-share-ami.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate EBS Snapshot by Sharing It](./AWS/aws.exfiltration.ec2-share-ebs-snapshot.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate RDS Snapshot by Sharing](./AWS/aws.exfiltration.rds-share-snapshot.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Backdoor an S3 Bucket via its Bucket Policy](./AWS/aws.exfiltration.s3-backdoor-bucket-policy.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Invoke Bedrock Model](./AWS/aws.impact.bedrock-invoke-model.md) | [AWS](./AWS/index.md) | Impact |
| [S3 Ransomware through batch file deletion](./AWS/aws.impact.s3-ransomware-batch-deletion.md) | [AWS](./AWS/index.md) | Impact |
| [S3 Ransomware through client-side encryption](./AWS/aws.impact.s3-ransomware-client-side-encryption.md) | [AWS](./AWS/index.md) | Impact |
| [S3 Ransomware through individual file deletion](./AWS/aws.impact.s3-ransomware-individual-deletion.md) | [AWS](./AWS/index.md) | Impact |
| [Console Login without MFA](./AWS/aws.initial-access.console-login-without-mfa.md) | [AWS](./AWS/index.md) | Initial Access |
| [Usage of EC2 Serial Console to push SSH public key](./AWS/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.md) | [AWS](./AWS/index.md) | Lateral Movement |
| [Usage of EC2 Instance Connect on multiple instances](./AWS/aws.lateral-movement.ec2-instance-connect.md) | [AWS](./AWS/index.md) | Lateral Movement |
| [Backdoor an IAM Role](./AWS/aws.persistence.iam-backdoor-role.md) | [AWS](./AWS/index.md) | Persistence |
| [Create an Access Key on an IAM User](./AWS/aws.persistence.iam-backdoor-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create an administrative IAM User](./AWS/aws.persistence.iam-create-admin-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create a backdoored IAM Role](./AWS/aws.persistence.iam-create-backdoor-role.md) | [AWS](./AWS/index.md) | Persistence |
| [Create a Login Profile on an IAM User](./AWS/aws.persistence.iam-create-user-login-profile.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Backdoor Lambda Function Through Resource-Based Policy](./AWS/aws.persistence.lambda-backdoor-function.md) | [AWS](./AWS/index.md) | Persistence |
| [Add a Malicious Lambda Extension](./AWS/aws.persistence.lambda-layer-extension.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Overwrite Lambda Function Code](./AWS/aws.persistence.lambda-overwrite-code.md) | [AWS](./AWS/index.md) | Persistence |
| [Create an IAM Roles Anywhere trust anchor](./AWS/aws.persistence.rolesanywhere-create-trust-anchor.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Generate temporary AWS credentials using GetFederationToken](./AWS/aws.persistence.sts-federation-token.md) | [AWS](./AWS/index.md) | Persistence |
| [Change IAM user password](./AWS/aws.privilege-escalation.iam-update-user-login-profile.md) | [AWS](./AWS/index.md) | Privilege Escalation |
| [Create/Update SageMaker Lifecycle Configuration for Privilege Escalation](./AWS/aws.privilege-escalation.sagemaker-update-lifecycle-config.md) | [AWS](./AWS/index.md) | Privilege Escalation |
| [Execute Command on Virtual Machine using Custom Script Extension](./azure/azure.execution.vm-custom-script-extension.md) | [Azure](./azure/index.md) | Execution |
| [Execute Commands on Virtual Machine using Run Command](./azure/azure.execution.vm-run-command.md) | [Azure](./azure/index.md) | Execution |
| [Export Disk Through SAS URL](./azure/azure.exfiltration.disk-export.md) | [Azure](./azure/index.md) | Exfiltration |
| [Create Azure VM Bastion shareable link](./azure/azure.persistence.create-bastion-shareable-link.md) | [Azure](./azure/index.md) | Persistence |
| [Create Admin EKS Access Entry](./EKS/eks.lateral-movement.create-access-entry.md) | [EKS](./EKS/index.md) | Lateral Movement |
| [Backdoor aws-auth EKS ConfigMap](./EKS/eks.persistence.backdoor-aws-auth-configmap.md) | [EKS](./EKS/index.md) | Persistence, Privilege Escalation |
| [Backdoor Entra ID application through service principal](./entra-id/entra-id.persistence.backdoor-application-sp.md) | [Entra ID](./entra-id/index.md) | Persistence, Privilege Escalation |
| [Backdoor Entra ID application](./entra-id/entra-id.persistence.backdoor-application.md) | [Entra ID](./entra-id/index.md) | Persistence, Privilege Escalation |
| [Create Guest User](./entra-id/entra-id.persistence.guest-user.md) | [Entra ID](./entra-id/index.md) | Persistence |
| [Create Hidden Scoped Role Assignment Through HiddenMembership AU](./entra-id/entra-id.persistence.hidden-au.md) | [Entra ID](./entra-id/index.md) | Persistence |
| [Create Application](./entra-id/entra-id.persistence.new-application.md) | [Entra ID](./entra-id/index.md) | Persistence, Privilege Escalation |
| [Create Sticky Backdoor User Through Restricted Management AU](./entra-id/entra-id.persistence.restricted-au.md) | [Entra ID](./entra-id/index.md) | Persistence |
| [Retrieve a High Number of Secret Manager secrets](./GCP/gcp.credential-access.secretmanager-retrieve-secrets.md) | [GCP](./GCP/index.md) | Credential Access |
| [Exfiltrate Compute Disk by sharing it](./GCP/gcp.exfiltration.share-compute-disk.md) | [GCP](./GCP/index.md) | Exfiltration |
| [Exfiltrate Compute Image by sharing it](./GCP/gcp.exfiltration.share-compute-image.md) | [GCP](./GCP/index.md) | Exfiltration |
| [Exfiltrate Compute Disk by sharing a snapshot](./GCP/gcp.exfiltration.share-compute-snapshot.md) | [GCP](./GCP/index.md) | Exfiltration |
| [Backdoor a GCP Service Account through its IAM Policy](./GCP/gcp.persistence.backdoor-service-account-policy.md) | [GCP](./GCP/index.md) | Persistence |
| [Create an Admin GCP Service Account](./GCP/gcp.persistence.create-admin-service-account.md) | [GCP](./GCP/index.md) | Persistence, Privilege Escalation |
| [Create a GCP Service Account Key](./GCP/gcp.persistence.create-service-account-key.md) | [GCP](./GCP/index.md) | Persistence, Privilege Escalation |
| [Invite an External User to a GCP Project](./GCP/gcp.persistence.invite-external-user.md) | [GCP](./GCP/index.md) | Persistence |
| [Dump All Secrets](./kubernetes/k8s.credential-access.dump-secrets.md) | [Kubernetes](./kubernetes/index.md) | Credential Access |
| [Steal Pod Service Account Token](./kubernetes/k8s.credential-access.steal-serviceaccount-token.md) | [Kubernetes](./kubernetes/index.md) | Credential Access |
| [Create Admin ClusterRole](./kubernetes/k8s.persistence.create-admin-clusterrole.md) | [Kubernetes](./kubernetes/index.md) | Persistence, Privilege Escalation |
| [Create Client Certificate Credential](./kubernetes/k8s.persistence.create-client-certificate.md) | [Kubernetes](./kubernetes/index.md) | Persistence |
| [Create Long-Lived Token](./kubernetes/k8s.persistence.create-token.md) | [Kubernetes](./kubernetes/index.md) | Persistence |
| [Container breakout via hostPath volume mount](./kubernetes/k8s.privilege-escalation.hostpath-volume.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
| [Privilege escalation through node/proxy permissions](./kubernetes/k8s.privilege-escalation.nodes-proxy.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
| [Run a Privileged Pod](./kubernetes/k8s.privilege-escalation.privileged-pod.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
| [Impersonate GCP Service Accounts](./GCP/gcp.privilege-escalation.impersonate-service-accounts.md) | [GCP](./GCP/index.md) | Privilege Escalation |
