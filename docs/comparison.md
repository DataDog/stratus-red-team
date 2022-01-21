# Comparison With Other Tools

## [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary

> Atomic Red Team™ is library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.

In 2021, Atomic Red Team added [support](https://redcanary.com/blog/art-cloud-containers/) for Cloud TTPs.

At the [time of writing](https://github.com/redcanaryco/atomic-red-team/blob/7576aff377781ba3546c0835e48bffc980b4cbc8/atomics/Indexes/Indexes-Markdown/index.md), Atomic Red Team has only 4 TTPs for AWS:

- AWS CloudTrail Changes
- AWS - Create a group and add a user to that group
- AWS - Create Access Key and Secret Key
- AWS - Create a new IAM user

While Atomic Red Team is an *awesome* tool for endpoint security, it wasn't built purposely for cloud environments.
In particular, it doesn't handle the pre-requisite infrastructure and configuration necessary to detonate TTPs, and leaves that to the user. 
For instance, [AWS - Create Access Key and Secret Key](https://github.com/redcanaryco/atomic-red-team/blob/7576aff377781ba3546c0835e48bffc980b4cbc8/atomics/T1098.001/T1098.001.md#atomic-test-3---aws---create-access-key-and-secret-key) requires you to create an IAM user prior to detonating the attack. Stratus Red Team packages this pre-requisite logic so you can detonate attack techniques without having to create any infrastructure or cloud configuration manually.

However, the attack technique format of Atomic Red Team is [based on YAML](https://github.com/redcanaryco/atomic-red-team/blob/7576aff377781ba3546c0835e48bffc980b4cbc8/atomics/T1098.001/T1098.001.yaml#L169-L196), and it's therefore easier to add new TTPs, even if they are not in the core of Atomic Red Team.

## [Leonidas](https://github.com/FSecureLABS/leonidas) by F-Secure (Nick Jones)

> Leonidas is a framework for executing attacker actions in the cloud. It provides a YAML-based format for defining cloud attacker tactics, techniques and procedures (TTPs) and their associated detection properties

While Stratus Red Team and Leonidas have similar goals, their implementation is fundamentally different.

- Leonidas is a [fully-fledged web application](https://github.com/FSecureLABS/leonidas/blob/master/docs/deploying-leonidas.md) you deploy in your AWS account using Terraform, and then a CodePipeline pipeline.
- Then, you use "Leo", the test case orchestrator, to hit the web API and detonate attack techniques. 
- Leonidas allows describing TTPs as [YAML](https://github.com/FSecureLABS/leonidas/blob/master/definitions/execution/modify-lambda-function-code.yml), making it easier to extend than Stratus Red Team. 
- Leonidas does not handle pre-requisites for detonating attack techniques.
- The attack techniques implemented by Leonidas are very granular, meaning it can be challenging to implement detection for them. See for instance: [STS Get Caller Identity](http://detectioninthe.cloud/discovery/sts_get_caller_identity/)
- Leonidas comes with a set of suggested threat detection rules. However, as its attack techniques are very granular, it is practically impossible to use them as-is in a real production environment, as they would trigger many false positives.

Stratus Red Team aims at being simpler to use (single binary) and does not require you to have prior infrastructure or configuration in your AWS account. Stratus Red Team focuses on a single thing: executing cloud attack tactics against a live environment, with minimal overhead. You can also use Stratus Red Team [programmatically](user-guide/programmatic-usage.md), from Go code, as a library.

## [Pacu](https://github.com/RhinoSecurityLabs/pacu) by Rhino Security  Labs

> Pacu is an open-source AWS exploitation framework, designed for offensive security testing against cloud environments. Created and maintained by Rhino Security Labs, Pacu allows penetration testers to exploit configuration flaws within an AWS account, using modules to easily expand its functionality.

Pacu is an offensive AWS exploitation framework, aimed at penetration testers. It implements various enumeration and exploitation methods, some straightforward and some advanced. For instance, [lambda__backdoor_new_roles](https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/lambda__backdoor_new_roles/main.py) creates a Lambda function and a CloudWatch Event causing all future IAM roles created in an AWS account to be backdoored automatically. Pacu aims at being used against existing AWS infrastructure. 

Stratus Red Team is self-contained and does not necessitate prior infrastructure or configuration in your cloud environment. You can also use it [programmatically](user-guide/programmatic-usage.md), from Go code, as a library.

## [Amazon GuardDuty Tester](https://github.com/awslabs/amazon-guardduty-tester)

Amazon GuardDuty Tester is helpful to trigger GuardDuty findings. However, it is tightly coupled with GuardDuty and is a product-specific tool, even within the AWS ecosystem.
If GuardDuty doesn't detect an attack technique, you won't find it in here.