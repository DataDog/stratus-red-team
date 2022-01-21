# Example: Registering and detonating a custom attack technique

To run:

```
go get github.com/datadog/stratus-red-team
go get -d
go run detonate_custom_technique.go
```

Sample output:
```
2022/01/21 15:51:56 Checking your authentication against the AWS API
2022/01/21 15:51:57 Warming up my-sample-attack-technique
2022/01/21 15:51:57 Initializing Terraform to spin up technique pre-requisites
2022/01/21 15:52:06 Applying Terraform to spin up technique pre-requisites
2022/01/21 15:52:16 IAM user stratus-red-team-giteeygx is ready
TTP is warm! Press enter to detonate it

2022/01/21 15:52:54 Not warming up - my-sample-attack-technique is already warm. Use --force to force
2022/01/21 15:52:54 The ARN of our IAM user is: arn:aws:iam::012345678912:user/stratus-red-team-giteeygx
2022/01/21 15:52:54 Cleaning up my-sample-attack-technique
2022/01/21 15:52:54 Cleaning up technique pre-requisites with terraform destroy
```