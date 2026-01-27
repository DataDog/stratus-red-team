
<style>
    .table-container {
        max-width: 80%; /* Ensures it doesn't go beyond the page */
        padding: 10px;
        margin-bottom: 20px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        font-size: 16px;
        white-space: nowrap; /* Prevents text wrapping in cells */
    }
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
        text-align: center;
    }
    .md-sidebar.md-sidebar--secondary { display: none; }
    .md-content { min-width: 100%; }
</style>

# MITRE ATT&CK Coverage by Platform

This provides coverage matrices of MITRE ATT&CK tactics and techniques currently covered by Stratus Red Team for different cloud platforms.
<h2>AWS</h2>
<div class="table-container"><table>
<thead><tr><th>Initial Access</th><th>Execution</th><th>Persistence</th><th>Privilege Escalation</th><th>Defense Evasion</th><th>Credential Access</th><th>Discovery</th><th>Lateral Movement</th><th>Exfiltration</th><th>Impact</th></tr></thead>
<tbody>
<tr><td><a href="../AWS/aws.initial-access.console-login-without-mfa">Console Login without MFA</a></td><td><a href="../AWS/aws.execution.ec2-launch-unusual-instances">Launch Unusual EC2 instances</a></td><td><a href="../AWS/aws.persistence.iam-backdoor-role">Backdoor an IAM Role</a></td><td><a href="../AWS/aws.execution.ec2-user-data">Execute Commands on EC2 Instance via User Data</a></td><td><a href="../AWS/aws.defense-evasion.cloudtrail-delete">Delete CloudTrail Trail</a></td><td><a href="../AWS/aws.credential-access.ec2-get-password-data">Retrieve EC2 Password Data</a></td><td><a href="../AWS/aws.discovery.ec2-enumerate-from-instance">Execute Discovery Commands on an EC2 Instance</a></td><td><a href="../AWS/aws.lateral-movement.ec2-serial-console-send-ssh-public-key">Usage of EC2 Serial Console to push SSH public key</a></td><td><a href="../AWS/aws.exfiltration.ec2-security-group-open-port-22-ingress">Open Ingress Port 22 on a Security Group</a></td><td><a href="../AWS/aws.impact.bedrock-invoke-model">Invoke Bedrock Model</a></td></tr>
<tr><td></td><td><a href="../AWS/aws.execution.ec2-user-data">Execute Commands on EC2 Instance via User Data</a></td><td><a href="../AWS/aws.persistence.iam-backdoor-user">Create an Access Key on an IAM User</a></td><td><a href="../AWS/aws.execution.sagemaker-update-lifecycle-config">Execute Commands on SageMaker Notebook Instance via Lifecycle Configuration</a></td><td><a href="../AWS/aws.defense-evasion.cloudtrail-event-selectors">Disable CloudTrail Logging Through Event Selectors</a></td><td><a href="../AWS/aws.credential-access.ec2-steal-instance-credentials">Steal EC2 Instance Credentials</a></td><td><a href="../AWS/aws.discovery.ec2-download-user-data">Download EC2 Instance User Data</a></td><td><a href="../AWS/aws.lateral-movement.ec2-instance-connect">Usage of EC2 Instance Connect on multiple instances</a></td><td><a href="../AWS/aws.exfiltration.ec2-share-ami">Exfiltrate an AMI by Sharing It</a></td><td><a href="../AWS/aws.impact.s3-ransomware-batch-deletion">S3 Ransomware through batch file deletion</a></td></tr>
<tr><td></td><td><a href="../AWS/aws.execution.sagemaker-update-lifecycle-config">Execute Commands on SageMaker Notebook Instance via Lifecycle Configuration</a></td><td><a href="../AWS/aws.persistence.iam-create-admin-user">Create an administrative IAM User</a></td><td><a href="../AWS/aws.persistence.iam-backdoor-user">Create an Access Key on an IAM User</a></td><td><a href="../AWS/aws.defense-evasion.cloudtrail-lifecycle-rule">CloudTrail Logs Impairment Through S3 Lifecycle Rule</a></td><td><a href="../AWS/aws.credential-access.secretsmanager-batch-retrieve-secrets">Retrieve a High Number of Secrets Manager secrets (Batch)</a></td><td><a href="../AWS/aws.discovery.ses-enumerate">Enumerate SES</a></td><td></td><td><a href="../AWS/aws.exfiltration.ec2-share-ebs-snapshot">Exfiltrate EBS Snapshot by Sharing It</a></td><td><a href="../AWS/aws.impact.s3-ransomware-client-side-encryption">S3 Ransomware through client-side encryption</a></td></tr>
<tr><td></td><td><a href="../AWS/aws.execution.ssm-send-command">Usage of ssm:SendCommand on multiple instances</a></td><td><a href="../AWS/aws.persistence.iam-create-backdoor-role">Create a backdoored IAM Role</a></td><td><a href="../AWS/aws.persistence.iam-create-admin-user">Create an administrative IAM User</a></td><td><a href="../AWS/aws.defense-evasion.cloudtrail-stop">Stop CloudTrail Trail</a></td><td><a href="../AWS/aws.credential-access.secretsmanager-retrieve-secrets">Retrieve a High Number of Secrets Manager secrets</a></td><td></td><td></td><td><a href="../AWS/aws.exfiltration.rds-share-snapshot">Exfiltrate RDS Snapshot by Sharing</a></td><td><a href="../AWS/aws.impact.s3-ransomware-individual-deletion">S3 Ransomware through individual file deletion</a></td></tr>
<tr><td></td><td><a href="../AWS/aws.execution.ssm-start-session">Usage of ssm:StartSession on multiple instances</a></td><td><a href="../AWS/aws.persistence.iam-create-user-login-profile">Create a Login Profile on an IAM User</a></td><td><a href="../AWS/aws.persistence.iam-create-user-login-profile">Create a Login Profile on an IAM User</a></td><td><a href="../AWS/aws.defense-evasion.dns-delete-logs">Delete DNS query logs</a></td><td><a href="../AWS/aws.credential-access.ssm-retrieve-securestring-parameters">Retrieve And Decrypt SSM Parameters</a></td><td></td><td></td><td><a href="../AWS/aws.exfiltration.s3-backdoor-bucket-policy">Backdoor an S3 Bucket via its Bucket Policy</a></td><td></td></tr>
<tr><td></td><td></td><td><a href="../AWS/aws.persistence.lambda-backdoor-function">Backdoor Lambda Function Through Resource-Based Policy</a></td><td><a href="../AWS/aws.persistence.lambda-layer-extension">Add a Malicious Lambda Extension</a></td><td><a href="../AWS/aws.defense-evasion.organizations-leave">Attempt to Leave the AWS Organization</a></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td><a href="../AWS/aws.persistence.lambda-layer-extension">Add a Malicious Lambda Extension</a></td><td><a href="../AWS/aws.persistence.rolesanywhere-create-trust-anchor">Create an IAM Roles Anywhere trust anchor</a></td><td><a href="../AWS/aws.defense-evasion.vpc-remove-flow-logs">Remove VPC Flow Logs</a></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td><a href="../AWS/aws.persistence.lambda-overwrite-code">Overwrite Lambda Function Code</a></td><td><a href="../AWS/aws.privilege-escalation.iam-update-user-login-profile">Change IAM user password</a></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td><a href="../AWS/aws.persistence.rolesanywhere-create-trust-anchor">Create an IAM Roles Anywhere trust anchor</a></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
<tr><td></td><td></td><td><a href="../AWS/aws.persistence.sts-federation-token">Generate temporary AWS credentials using GetFederationToken</a></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>
</tbody>
</table>
</div>
<h2>Azure</h2>
<div class="table-container"><table>
<thead><tr><th>Execution</th><th>Persistence</th><th>Exfiltration</th><th>Impact</th></tr></thead>
<tbody>
<tr><td><a href="../Azure/azure.execution.vm-custom-script-extension">Execute Command on Virtual Machine using Custom Script Extension</a></td><td><a href="../Azure/azure.persistence.create-bastion-shareable-link">Create Azure VM Bastion shareable link</a></td><td><a href="../Azure/azure.exfiltration.disk-export">Export Disk Through SAS URL</a></td><td><a href="../Azure/azure.impact.blob-ransomware-individual-file-deletion">Azure ransomware via Storage Account blob deletion</a></td></tr>
<tr><td><a href="../Azure/azure.execution.vm-run-command">Execute Commands on Virtual Machine using Run Command</a></td><td></td><td></td><td></td></tr>
</tbody>
</table>
</div>
<h2>GCP</h2>
<div class="table-container"><table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Credential Access</th><th>Exfiltration</th></tr></thead>
<tbody>
<tr><td><a href="../GCP/gcp.persistence.backdoor-service-account-policy">Backdoor a GCP Service Account through its IAM Policy</a></td><td><a href="../GCP/gcp.persistence.create-admin-service-account">Create an Admin GCP Service Account</a></td><td><a href="../GCP/gcp.credential-access.secretmanager-retrieve-secrets">Retrieve a High Number of Secret Manager secrets</a></td><td><a href="../GCP/gcp.exfiltration.share-compute-disk">Exfiltrate Compute Disk by sharing it</a></td></tr>
<tr><td><a href="../GCP/gcp.persistence.create-admin-service-account">Create an Admin GCP Service Account</a></td><td><a href="../GCP/gcp.persistence.create-service-account-key">Create a GCP Service Account Key</a></td><td></td><td><a href="../GCP/gcp.exfiltration.share-compute-image">Exfiltrate Compute Image by sharing it</a></td></tr>
<tr><td><a href="../GCP/gcp.persistence.create-service-account-key">Create a GCP Service Account Key</a></td><td><a href="../GCP/gcp.privilege-escalation.impersonate-service-accounts">Impersonate GCP Service Accounts</a></td><td></td><td><a href="../GCP/gcp.exfiltration.share-compute-snapshot">Exfiltrate Compute Disk by sharing a snapshot</a></td></tr>
<tr><td><a href="../GCP/gcp.persistence.invite-external-user">Invite an External User to a GCP Project</a></td><td></td><td></td><td></td></tr>
</tbody>
</table>
</div>
<h2>Kubernetes</h2>
<div class="table-container"><table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Credential Access</th></tr></thead>
<tbody>
<tr><td><a href="../Kubernetes/k8s.persistence.create-admin-clusterrole">Create Admin ClusterRole</a></td><td><a href="../Kubernetes/k8s.persistence.create-admin-clusterrole">Create Admin ClusterRole</a></td><td><a href="../Kubernetes/k8s.credential-access.dump-secrets">Dump All Secrets</a></td></tr>
<tr><td><a href="../Kubernetes/k8s.persistence.create-client-certificate">Create Client Certificate Credential</a></td><td><a href="../Kubernetes/k8s.privilege-escalation.hostpath-volume">Container breakout via hostPath volume mount</a></td><td><a href="../Kubernetes/k8s.credential-access.steal-serviceaccount-token">Steal Pod Service Account Token</a></td></tr>
<tr><td><a href="../Kubernetes/k8s.persistence.create-token">Create Long-Lived Token</a></td><td><a href="../Kubernetes/k8s.privilege-escalation.nodes-proxy">Privilege escalation through node/proxy permissions</a></td><td></td></tr>
<tr><td></td><td><a href="../Kubernetes/k8s.privilege-escalation.privileged-pod">Run a Privileged Pod</a></td><td></td></tr>
</tbody>
</table>
</div>
<h2>Entra ID</h2>
<div class="table-container"><table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th></tr></thead>
<tbody>
<tr><td><a href="../Entra ID/entra-id.persistence.backdoor-application-sp">Backdoor Entra ID application through service principal</a></td><td><a href="../Entra ID/entra-id.persistence.backdoor-application-sp">Backdoor Entra ID application through service principal</a></td></tr>
<tr><td><a href="../Entra ID/entra-id.persistence.backdoor-application">Backdoor Entra ID application</a></td><td><a href="../Entra ID/entra-id.persistence.backdoor-application">Backdoor Entra ID application</a></td></tr>
<tr><td><a href="../Entra ID/entra-id.persistence.guest-user">Create Guest User</a></td><td><a href="../Entra ID/entra-id.persistence.new-application">Create Application</a></td></tr>
<tr><td><a href="../Entra ID/entra-id.persistence.hidden-au">Create Hidden Scoped Role Assignment Through HiddenMembership AU</a></td><td></td></tr>
<tr><td><a href="../Entra ID/entra-id.persistence.new-application">Create Application</a></td><td></td></tr>
<tr><td><a href="../Entra ID/entra-id.persistence.restricted-au">Create Sticky Backdoor User Through Restricted Management AU</a></td><td></td></tr>
</tbody>
</table>
</div>
<h2>EKS</h2>
<div class="table-container"><table>
<thead><tr><th>Persistence</th><th>Privilege Escalation</th><th>Lateral Movement</th></tr></thead>
<tbody>
<tr><td><a href="../EKS/eks.persistence.backdoor-aws-auth-configmap">Backdoor aws-auth EKS ConfigMap</a></td><td><a href="../EKS/eks.persistence.backdoor-aws-auth-configmap">Backdoor aws-auth EKS ConfigMap</a></td><td><a href="../EKS/eks.lateral-movement.create-access-entry">Create Admin EKS Access Entry</a></td></tr>
</tbody>
</table>
</div>
