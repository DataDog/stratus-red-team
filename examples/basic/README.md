# Example: programatically detonating a Stratus Red Team attack technique

```
go get github.com/datadog/stratus-red-team
go get -d
go run detonate_stratus_red_team_technique.go
```

Sample output:
```
aws.defense-evasion.stop-cloudtrail
2022/01/21 15:55:11 Checking your authentication against the AWS API
2022/01/21 15:55:12 Warming up aws.defense-evasion.stop-cloudtrail
2022/01/21 15:55:12 Initializing Terraform to spin up technique pre-requisites
2022/01/21 15:55:20 Applying Terraform to spin up technique pre-requisites
2022/01/21 15:55:45 CloudTrail trail arn:aws:cloudtrail:us-east-1:751353041310:trail/my-cloudtrail-trail ready
TTP is warm! Press enter to detonate it

2022/01/21 15:55:49 Not warming up - aws.defense-evasion.stop-cloudtrail is already warm. Use --force to force
2022/01/21 15:55:49 Stopping CloudTrail trail my-cloudtrail-trail
2022/01/21 15:55:49 Cleaning up aws.defense-evasion.stop-cloudtrail
2022/01/21 15:55:49 Reverting detonation of technique aws.defense-evasion.stop-cloudtrail
2022/01/21 15:55:49 Restarting CloudTrail trail my-cloudtrail-trail
2022/01/21 15:55:50 Cleaning up technique pre-requisites with terraform destroy
```