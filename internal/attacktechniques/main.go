package attacktechniques

import (
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/ec2-get-password-data"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/credential-access/ec2-instance-credentials"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/disable-cloudtrail"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/leave-organization"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/defense-evasion/remove-vpc-flow-logs"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/discovery/discovery-commands-ec2-instance-role"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ami-sharing"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ebs-snapshot-share"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/s3-bucket-backdoor-bucket-policy"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/securitygroup-open-port-22-to-internet"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/backdoor-lambda-function"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-role-backdoor-existing"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-user-backdoor-existing"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-user-create-login-profile"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/iam-user-create-new"
)
