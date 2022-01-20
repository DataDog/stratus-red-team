# AWS

This page contains the Stratus attack techniques for AWS, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.


## Credential Access

- [Retrieve EC2 password data](./aws.credential-access.ec2-get-password-data.md)

- [Steal EC2 Instance Credentials](./aws.credential-access.ec2-instance-credentials.md)

- [Retrieve a High Number of Secrets Manager secrets](./aws.credential-access.secretsmanager-retrieve-secrets.md)


## Defense Evasion

- [Delete a CloudTrail Trail](./aws.defense-evasion.delete-cloudtrail.md)

- [Stop a CloudTrail Trail](./aws.defense-evasion.stop-cloudtrail.md)

- [Attempt to Leave the AWS Organization](./aws.defense-evasion.leave-organization.md)

- [Remove VPC flow logs](./aws.defense-evasion.remove-vpc-flow-logs.md)


## Discovery

- [Execute discovery commands on an EC2 instance](./aws.discovery.basic-enumeration-from-ec2-instance.md)


## Exfiltration

- [Exfiltrate an AMI by AMI Sharing](./aws.exfiltration.ami-sharing.md)

- [Exfiltrate EBS Snapshot through snapshot sharing](./aws.exfiltration.ebs-snapshot-shared-with-external-account.md)

- [Backdoor an S3 Bucket via its Bucket Policy](./aws.exfiltration.backdoor-s3-bucket-policy.md)

- [Open Ingress Port 22 on a Security Group](./aws.exfiltration.open-port-22-ingress-on-security-group.md)


## Persistence

- [Backdoor Lambda Function Through Resource-Based Policy](./aws.persistence.backdoor-lambda-function.md)

- [Backdoor an existing IAM Role](./aws.persistence.backdoor-iam-role.md)

- [Create an IAM Access Key on an IAM User](./aws.persistence.backdoor-iam-user.md)

- [Create a Login Profile on an IAM user](./aws.persistence.iam-user-create-login-profile.md)

- [Create an administrative IAM User](./aws.persistence.malicious-iam-user.md)


## Privilege Escalation

- [Create an IAM Access Key on an IAM User](./aws.persistence.backdoor-iam-user.md)

- [Create a Login Profile on an IAM user](./aws.persistence.iam-user-create-login-profile.md)

- [Create an administrative IAM User](./aws.persistence.malicious-iam-user.md)

