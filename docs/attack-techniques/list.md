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
| [Retrieve a High Number of Secrets Manager secrets](./AWS/aws.credential-access.secretsmanager-retrieve-secrets.md) | [AWS](./AWS/index.md) | Credential Access |
| [Retrieve And Decrypt SSM Parameters](./AWS/aws.credential-access.ssm-retrieve-securestring-parameters.md) | [AWS](./AWS/index.md) | Credential Access |
| [Delete CloudTrail Trail](./AWS/aws.defense-evasion.cloudtrail-delete.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Disable CloudTrail Logging Through Event Selectors](./AWS/aws.defense-evasion.cloudtrail-event-selectors.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [CloudTrail Logs Impairment Through S3 Lifecycle Rule](./AWS/aws.defense-evasion.cloudtrail-lifecycle-rule.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Stop CloudTrail Trail](./AWS/aws.defense-evasion.cloudtrail-stop.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Attempt to Leave the AWS Organization](./AWS/aws.defense-evasion.organizations-leave.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Remove VPC Flow Logs](./AWS/aws.defense-evasion.vpc-remove-flow-logs.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Execute Discovery Commands on an EC2 Instance](./AWS/aws.discovery.ec2-enumerate-from-instance.md) | [AWS](./AWS/index.md) | Discovery |
| [Download EC2 Instance User Data](./AWS/aws.discovery.ec2-download-user-data.md) | [AWS](./AWS/index.md) | Discovery |
| [Launch Unusual EC2 instances](./AWS/aws.execution.ec2-launch-unusual-instances.md) | [AWS](./AWS/index.md) | Execution |
| [Execute Commands on EC2 Instance via User Data](./AWS/aws.execution.ec2-user-data.md) | [AWS](./AWS/index.md) | Execution, Privilege Escalation |
| [Open Ingress Port 22 on a Security Group](./AWS/aws.exfiltration.ec2-security-group-open-port-22-ingress.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate an AMI by Sharing It](./AWS/aws.exfiltration.ec2-share-ami.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate EBS Snapshot by Sharing It](./AWS/aws.exfiltration.ec2-share-ebs-snapshot.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate RDS Snapshot by Sharing](./AWS/aws.exfiltration.rds-share-snapshot.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Backdoor an S3 Bucket via its Bucket Policy](./AWS/aws.exfiltration.s3-backdoor-bucket-policy.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Console Login without MFA](./AWS/aws.initial-access.console-login-without-mfa.md) | [AWS](./AWS/index.md) | Initial Access |
| [Backdoor an IAM Role](./AWS/aws.persistence.iam-backdoor-role.md) | [AWS](./AWS/index.md) | Persistence |
| [Create an Access Key on an IAM User](./AWS/aws.persistence.iam-backdoor-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create an administrative IAM User](./AWS/aws.persistence.iam-create-admin-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create a Login Profile on an IAM User](./AWS/aws.persistence.iam-create-user-login-profile.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Backdoor Lambda Function Through Resource-Based Policy](./AWS/aws.persistence.lambda-backdoor-function.md) | [AWS](./AWS/index.md) | Persistence |
| [Overwrite Lambda Function Code](./AWS/aws.persistence.lambda-overwrite-code.md) | [AWS](./AWS/index.md) | Persistence |
| [Execute Command on Virtual Machine using Custom Script Extension](./azure/azure.execution.vm-custom-script-extension.md) | [Azure](./azure/index.md) | Execution |
| [Execute Commands on Virtual Machine using Run Command](./azure/azure.execution.vm-run-command.md) | [Azure](./azure/index.md) | Execution |
| [Export Disk Through SAS URL](./azure/azure.exfiltration.disk-export.md) | [Azure](./azure/index.md) | Exfiltration |
| [Dump All Secrets](./kubernetes/k8s.credential-access.dump-secrets.md) | [Kubernetes](./kubernetes/index.md) | Credential Access |
| [Steal Pod Service Account Token](./kubernetes/k8s.credential-access.steal-serviceaccount-token.md) | [Kubernetes](./kubernetes/index.md) | Credential Access |
| [Create Admin ClusterRole](./kubernetes/k8s.persistence.create-admin-clusterrole.md) | [Kubernetes](./kubernetes/index.md) | Persistence, Privilege Escalation |
| [Create Long-Lived Token](./kubernetes/k8s.persistence.create-token.md) | [Kubernetes](./kubernetes/index.md) | Persistence |
| [Container breakout via hostPath volume mount](./kubernetes/k8s.privilege-escalation.hostpath-volume.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
| [Privilege escalation through node/proxy permissions](./kubernetes/k8s.privilege-escalation.nodes-proxy.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
| [Run a Privileged Pod](./kubernetes/k8s.privilege-escalation.privileged-pod.md) | [Kubernetes](./kubernetes/index.md) | Privilege Escalation |
