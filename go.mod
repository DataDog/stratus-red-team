module github.com/datadog/stratus-red-team

go 1.17

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources v1.0.0
	github.com/aws/aws-sdk-go-v2 v1.13.0
	github.com/aws/aws-sdk-go-v2/config v1.13.0
	github.com/aws/aws-sdk-go-v2/credentials v1.8.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.13.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.26.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.14.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.17.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.12.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.16.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.23.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.13.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.20.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.14.0
	github.com/aws/smithy-go v1.10.0
	github.com/fatih/color v1.13.0
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/google/uuid v1.3.0
	github.com/hashicorp/terraform-exec v0.15.0
	github.com/jedib0t/go-pretty/v6 v6.2.4
	github.com/spf13/cobra v1.3.0
	github.com/stretchr/testify v1.7.0
	k8s.io/api v0.23.3
	k8s.io/apimachinery v0.23.3
	k8s.io/client-go v0.23.3
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.0.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.4.0 // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.10.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.6.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.7.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.10.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/browser v0.0.0-20210115035449-ce105d075bb4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.2.0 // indirect
	golang.org/x/net v0.0.0-20220425223048-2871e0cb64e4 // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/klog/v2 v2.30.0 // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/utils v0.0.0-20211116205334-6203023598ed // indirect
	sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

require (
	cloud.google.com/go/storage v1.14.0 // indirect
	github.com/aws/aws-sdk-go v1.40.56 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.5.11 // indirect
	github.com/hashicorp/go-version v1.4.0
	github.com/hashicorp/hc-install v0.3.2
	github.com/hashicorp/terraform-json v0.13.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/klauspost/compress v1.13.0 // indirect
	github.com/zclconf/go-cty v1.9.1 // indirect
	golang.org/x/crypto v0.0.0-20220511200225-c6db032c6c88 // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/api v0.63.0 // indirect
	google.golang.org/grpc v1.43.0 // indirect
)
