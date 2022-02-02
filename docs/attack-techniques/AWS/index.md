# AWS

This page contains the Stratus attack techniques for AWS, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.


## Credential Access

- [Retrieve EC2 Password Data](./aws.credential-access.ec2-get-password-data.md)

- [Steal EC2 Instance Credentials](./aws.credential-access.ec2-steal-instance-credentials.md)

- [Retrieve a High Number of Secrets Manager secrets](./aws.credential-access.secretsmanager-retrieve-secrets.md)

- [Retrieve And Decrypt SSM Parameters](./aws.credential-access.ssm-retrieve-securestring-parameters.md)


## Defense Evasion

- [Delete CloudTrail Trail](./aws.defense-evasion.cloudtrail-delete.md)

- [Disable CloudTrail Logging Through Event Selectors](./aws.defense-evasion.cloudtrail-event-selectors.md)

- [CloudTrail Logs Impairment Through S3 Lifecycle Rule](./aws.defense-evasion.cloudtrail-lifecycle-rule.md)

- [Stop CloudTrail Trail](./aws.defense-evasion.cloudtrail-stop.md)

- [Attempt to Leave the AWS Organization](./aws.defense-evasion.organizations-leave.md)

- [Remove VPC Flow Logs](./aws.defense-evasion.vpc-remove-flow-logs.md)


## Discovery

- [Execute Discovery Commands on an EC2 Instance](./aws.discovery.ec2-enumerate-from-instance.md)

- [Download EC2 Instance User Data](./aws.discovery.ec2-download-user-data.md)


## Execution

- [Execute Commands on EC2 Instance via User Data](./aws.execution.ec2-user-data.md)


## Exfiltration

- [Open Ingress Port 22 on a Security Group](./aws.exfiltration.ec2-security-group-open-port-22-ingress.md)

- [Exfiltrate an AMI by Sharing It](./aws.exfiltration.ec2-share-ami.md)

- [Exfiltrate EBS Snapshot by Sharing It](./aws.exfiltration.ec2-share-ebs-snapshot.md)

- [Exfiltrate RDS Snapshot by Sharing](./aws.exfiltration.rds-share-snapshot.md)

- [Backdoor an S3 Bucket via its Bucket Policy](./aws.exfiltration.s3-backdoor-bucket-policy.md)


## Persistence

- [Backdoor an IAM Role](./aws.persistence.iam-backdoor-role.md)

- [Create an Access Key on an IAM User](./aws.persistence.iam-backdoor-user.md)

- [Create an administrative IAM User](./aws.persistence.iam-create-admin-user.md)

- [Create a Login Profile on an IAM User](./aws.persistence.iam-create-user-login-profile.md)

- [Backdoor Lambda Function Through Resource-Based Policy](./aws.persistence.lambda-backdoor-function.md)


## Privilege Escalation

- [Execute Commands on EC2 Instance via User Data](./aws.execution.ec2-user-data.md)

- [Create an Access Key on an IAM User](./aws.persistence.iam-backdoor-user.md)

- [Create an administrative IAM User](./aws.persistence.iam-create-admin-user.md)

- [Create a Login Profile on an IAM User](./aws.persistence.iam-create-user-login-profile.md)

