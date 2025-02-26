
# MITRE ATT&CK Coverage by Platform

This provides coverage matrices of MITRE ATT&CK tactics and techniques currently covered by Stratus Red Team for different cloud platforms.

<!DOCTYPE html>
<html>
<head>
	<title>MITRE ATT&CK Coverage</title>
	<style>
		body { font-family: SFMono-Regular, Consolas, Menlo, monospace; sans-serif; margin: 20px; }
		table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 16px; }
		th, td { border: 1px solid #ddd; padding: 8px; text-align: center; }
		th { background-color: #f4f4f4; font-weight: bold; font-size: 18px; color: #000; }
		td { font-weight: normal; color: #7e56c2; }
		tr:hover { background-color: #f1f1f1; }
		td:hover { background-color: #e9e9ff; color: #5a3ea8; cursor: pointer; }
		h1 { font-weight: 300; color: #333; }
		h2 { color: #0000008a; text-transform: capitalize; }
	</style>
</head>
<body>
<h2>GCP</h2>
<table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Credential Access</th><th>Exfiltration</th></tr></thead>
<tbody>
<tr><td>Backdoor a GCP Service Account through its IAM Policy</td><td>Create an Admin GCP Service Account</td><td>Retrieve a High Number of Secret Manager secrets</td><td>Exfiltrate Compute Disk by sharing it</td></tr>
<tr><td>Create an Admin GCP Service Account</td><td>Create a GCP Service Account Key</td><td></td><td>Exfiltrate Compute Image by sharing it</td></tr>
<tr><td>Create a GCP Service Account Key</td><td>Impersonate GCP Service Accounts</td><td></td><td>Exfiltrate Compute Disk by sharing a snapshot</td></tr>
<tr><td>Invite an External User to a GCP Project</td><td></td><td></td><td></td></tr>
</tbody>
</table>
<h2>kubernetes</h2>
<table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Credential Access</th></tr></thead>
<tbody>
<tr><td>Create Admin ClusterRole</td><td>Create Admin ClusterRole</td><td>Dump All Secrets</td></tr>
<tr><td>Create Client Certificate Credential</td><td>Container breakout via hostPath volume mount</td><td>Steal Pod Service Account Token</td></tr>
<tr><td>Create Long-Lived Token</td><td>Privilege escalation through node/proxy permissions</td><td></td></tr>
<tr><td></td><td>Run a Privileged Pod</td><td></td></tr>
</tbody>
</table>
<h2>AWS</h2>
<table>
<thead><tr><th>Initial Access</th><th>Execution</th><th>Persistence</th><th>Privilege Escalation</th><th>Defense Evasion</th><th>Credential Access</th><th>Discovery</th><th>Lateral Movement</th><th>Exfiltration</th><th>Impact</th></tr></thead>
<tbody>
<tr><td>Console Login without MFA</td><td>Launch Unusual EC2 instances</td><td>Backdoor an IAM Role</td><td>Execute Commands on EC2 Instance via User Data</td><td>Delete CloudTrail Trail</td><td>Retrieve EC2 Password Data</td><td>Execute Discovery Commands on an EC2 Instance</td><td>Usage of EC2 Serial Console to push SSH public key</td><td>Open Ingress Port 22 on a Security Group</td><td>Invoke Bedrock Model</td></tr>
<tr><td></td><td>Execute Commands on EC2 Instance via User Data</td><td>Create an Access Key on an IAM User</td><td>Create an Access Key on an IAM User</td><td>Disable CloudTrail Logging Through Event Selectors</td><td>Steal EC2 Instance Credentials</td><td>Download EC2 Instance User Data</td><td>Usage of EC2 Instance Connect on multiple instances</td><td>Exfiltrate an AMI by Sharing It</td><td>S3 Ransomware through batch file deletion</td></tr>
<tr><td></td><td>Usage of ssm:SendCommand on multiple instances</td><td>Create an administrative IAM User</td><td>Create an administrative IAM User</td><td>CloudTrail Logs Impairment Through S3 Lifecycle Rule</td><td>Retrieve a High Number of Secrets Manager secrets (Batch)</td><td>Enumerate SES</td><td></td><td>Exfiltrate EBS Snapshot by Sharing It</td><td>S3 Ransomware through client-side encryption</td></tr>
<tr><td></td><td>Usage of ssm:StartSession on multiple instances</td><td>Create a backdoored IAM Role</td><td>Create a Login Profile on an IAM User</td><td>Stop CloudTrail Trail</td><td>Retrieve a High Number of Secrets Manager secrets</td><td></td><td></td><td>Exfiltrate RDS Snapshot by Sharing</td><td>S3 Ransomware through individual file deletion</td></tr>
<tr><td></td><td></td><td>Create a Login Profile on an IAM User</td><td>Add a Malicious Lambda Extension</td><td>Delete DNS query logs</td><td>Retrieve And Decrypt SSM Parameters</td><td></td><td></td><td>Backdoor an S3 Bucket via its Bucket Policy</td><td></td></tr>
<tr><td></td><td></td><td>Backdoor Lambda Function Through Resource-Based Policy</td><td>Create an IAM Roles Anywhere trust anchor</td><td>Attempt to Leave the AWS Organization</td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td>Add a Malicious Lambda Extension</td><td>Change IAM user password</td><td>Remove VPC Flow Logs</td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td>Overwrite Lambda Function Code</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td>Create an IAM Roles Anywhere trust anchor</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td>Generate temporary AWS credentials using GetFederationToken</td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
</tbody>
</table>
<h2>azure</h2>
<table>
<thead><tr><th>Execution</th><th>Persistence</th><th>Exfiltration</th></tr></thead>
<tbody>
<tr><td>Execute Command on Virtual Machine using Custom Script Extension</td><td>Create Azure VM Bastion shareable link</td><td>Export Disk Through SAS URL</td></tr>
<tr><td>Execute Commands on Virtual Machine using Run Command</td><td></td><td></td></tr>
</tbody>
</table>
<h2>EKS</h2>
<table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Lateral Movement</th></tr></thead>
<tbody>
<tr><td>Backdoor aws-auth EKS ConfigMap</td><td>Backdoor aws-auth EKS ConfigMap</td><td>Create Admin EKS Access Entry</td></tr>
</tbody>
</table>
<h2>entra-id</h2>
<table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th></tr></thead>
<tbody>
<tr><td>Backdoor Entra ID application through service principal</td><td>Backdoor Entra ID application through service principal</td></tr>
<tr><td>Backdoor Entra ID application</td><td>Backdoor Entra ID application</td></tr>
<tr><td>Create Guest User</td><td>Create Application</td></tr>
<tr><td>Create Hidden Scoped Role Assignment Through HiddenMembership AU</td><td></td></tr>
<tr><td>Create Application</td><td></td></tr>
<tr><td>Create Sticky Backdoor User Through Restricted Management AU</td><td></td></tr>
</tbody>
</table>

</body>
</html>