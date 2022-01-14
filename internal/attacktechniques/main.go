package attacktechniques

import (
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/ebs_snapshot_share"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/exfiltration/s3_backdoor_bucket_policy"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/backdoor_iam_user"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/backdoor_role"
	_ "github.com/datadog/stratus-red-team/internal/attacktechniques/aws/persistence/malicious_iam_user"
)
