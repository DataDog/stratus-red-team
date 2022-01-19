---
hide:
  - toc
---

# List of all Attack Techniques

This page contains the list of all Stratus Attack Techniques.

| Name   | Platform | MITRE ATT&CK Tactics |
| :----: | :------: | :------------------: |
| [Retrieve EC2 password data](./AWS/aws.credential-access.ec2-get-password-data.md) | [AWS](./AWS/index.md) | Credential Access |
| [Steal EC2 Instance Credentials](./AWS/aws.credential-access.ec2-instance-credentials.md) | [AWS](./AWS/index.md) | Credential Access |
| [Stop a CloudTrail Trail](./AWS/aws.defense-evasion.stop-cloudtrail.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Remove VPC flow logs](./AWS/aws.defense-evasion.remove-vpc-flow-logs.md) | [AWS](./AWS/index.md) | Defense Evasion |
| [Execute discovery commands on an EC2 instance](./AWS/aws.discovery.basic-enumeration-from-ec2-instance.md) | [AWS](./AWS/index.md) | Discovery |
| [Exfiltrate an AMI by AMI Sharing](./AWS/aws.exfiltration.ami-sharing.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Exfiltrate EBS Snapshot through snapshot sharing](./AWS/aws.exfiltration.ebs-snapshot-shared-with-external-account.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Backdoor an S3 Bucket via its Bucket Policy](./AWS/aws.exfiltration.backdoor-s3-bucket-policy.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Open Ingress Port 22 on a Security Group](./AWS/aws.exfiltration.open-port-22-ingress-on-security-group.md) | [AWS](./AWS/index.md) | Exfiltration |
| [Backdoor Lambda Function Through Resource-Based Policy](./AWS/aws.persistence.backdoor-lambda-function.md) | [AWS](./AWS/index.md) | Persistence |
| [Backdoor an existing IAM Role](./AWS/aws.persistence.backdoor-iam-role.md) | [AWS](./AWS/index.md) | Persistence |
| [Create an IAM Access Key on an IAM User](./AWS/aws.persistence.backdoor-iam-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create a Login Profile on an IAM user](./AWS/aws.persistence.iam-user-create-login-profile.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
| [Create an administrative IAM User](./AWS/aws.persistence.malicious-iam-user.md) | [AWS](./AWS/index.md) | Persistence, Privilege Escalation |
