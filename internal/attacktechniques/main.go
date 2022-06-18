package attacktechniques

import (
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/ec2-get-password-data"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/ec2-steal-instance-credentials"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/secretsmanager-retrieve-secrets"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/ssm-retrieve-securestring-parameters"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/cloudtrail-delete"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/cloudtrail-event-selectors"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/cloudtrail-lifecycle-rule"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/cloudtrail-stop"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/organizations-leave"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/vpc-remove-flow-logs"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/discovery/ec2-enumerate-from-instance"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/discovery/ec2-get-user-data"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/execution/ec2-user-data"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ec2-security-group-open-port-22-ingress"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ec2-share-ami"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ec2-share-ebs-snapshot"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/rds-share-snapshot"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/s3-backdoor-bucket-policy"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/initial-access/console-login-without-mfa"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-backdoor-role"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-backdoor-user"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-create-admin-user"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-create-user-login-profile"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/lambda-backdoor-function"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/lambda-update-function"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/azure/execution/vm-run-command"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/azure/exfiltration/disk-export"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/credential-access/dump-secrets"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/credential-access/steal-serviceaccount-token"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/persistence/create-admin-clusterrole"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/privilege-escalation/hostpath-volume"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/privilege-escalation/nodes-proxy"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/k8s/privilege-escalation/privileged-pod"
)
