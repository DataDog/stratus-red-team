# Comparison With Other Tools

## [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) by Red Canary

> Atomic Red Team™ is library of tests mapped to the MITRE ATT&CK® framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.

In 2021, Atomic Red Team added [support](https://redcanary.com/blog/art-cloud-containers/) for Cloud TTPs. In the summer 2022, Atomic Red Team also started [leveraging Stratus Red Team](https://github.com/search?q=repo%3Aredcanaryco%2Fatomic-red-team%20%22stratus%20red%20team%22&type=code) to execute some of its cloud attack techniques.

Atomic Red Team has very few cloud TTPs it implements itself. While Atomic Red Team is an *awesome* tool for endpoint security, it wasn't built purposely for cloud environments.
In particular, it doesn't handle the prerequisite infrastructure and configuration necessary to detonate TTPs, and leaves that to the user. 
For instance, [AWS - Create Access Key and Secret Key](https://github.com/redcanaryco/atomic-red-team/blob/7576aff377781ba3546c0835e48bffc980b4cbc8/atomics/T1098.001/T1098.001.md#atomic-test-3---aws---create-access-key-and-secret-key) requires you to create an IAM user prior to detonating the attack. Stratus Red Team packages this prerequisite logic, so you can detonate attack techniques without having to create any infrastructure or cloud configuration manually.

However, the attack technique format of Atomic Red Team is [based on YAML](https://github.com/redcanaryco/atomic-red-team/blob/7576aff377781ba3546c0835e48bffc980b4cbc8/atomics/T1098.001/T1098.001.yaml#L169-L196), and it's therefore easier to add new TTPs, even if they are not in the core of Atomic Red Team.

## [Leonidas](https://github.com/FSecureLABS/leonidas) by F-Secure (Nick Jones)

> Leonidas is a framework for executing attacker actions in the cloud. It provides a YAML-based format for defining cloud attacker tactics, techniques and procedures (TTPs) and their associated detection properties

While Stratus Red Team and Leonidas have similar goals, their implementation is fundamentally different.

- Leonidas is a [fully-fledged web application](https://github.com/FSecureLABS/leonidas/blob/master/docs/deploying-leonidas.md) you deploy in your AWS account using Terraform, and then a CodePipeline pipeline.
- Then, you use "Leo", the test case orchestrator, to hit the web API and detonate attack techniques. 
- Leonidas allows describing TTPs as [YAML](https://github.com/FSecureLABS/leonidas/blob/master/definitions/execution/modify-lambda-function-code.yml), making it easier to extend than Stratus Red Team. 
- Leonidas does not handle prerequisites for detonating attack techniques.
- The attack techniques implemented by Leonidas are very granular, meaning it can be challenging to implement detection for them. See for instance: [STS Get Caller Identity](http://detectioninthe.cloud/discovery/sts_get_caller_identity/)
- Leonidas comes with a set of suggested threat detection rules. However, as its attack techniques are very granular, it is practically impossible to use them as-is in a real production environment, as they would trigger many false positives.

Stratus Red Team aims at being simpler to use (single binary) and does not require you to have prior infrastructure or configuration in your AWS account. Stratus Red Team focuses on a single thing: executing cloud attack tactics against a live environment, with minimal overhead. You can also use Stratus Red Team [programmatically](user-guide/programmatic-usage.md), from Go code, as a library.

## [Pacu](https://github.com/RhinoSecurityLabs/pacu) by Rhino Security  Labs

> Pacu is an open-source AWS exploitation framework, designed for offensive security testing against cloud environments. Created and maintained by Rhino Security Labs, Pacu allows penetration testers to exploit configuration flaws within an AWS account, using modules to easily expand its functionality.

Pacu is an offensive AWS exploitation framework, aimed at penetration testers. It implements various enumeration and exploitation methods, some straightforward and some advanced. For instance, [lambda__backdoor_new_roles](https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/lambda__backdoor_new_roles/main.py) creates a Lambda function and a CloudWatch Event causing all future IAM roles created in an AWS account to be backdoored automatically. Pacu aims at being used against existing AWS infrastructure. 

Stratus Red Team is self-contained and does not necessitate prior infrastructure or configuration in your cloud environment. You can also use it [programmatically](user-guide/programmatic-usage.md), from Go code, as a library.

## [Amazon GuardDuty Tester](https://github.com/awslabs/amazon-guardduty-tester) by AWS

Amazon GuardDuty Tester is helpful to trigger GuardDuty findings. However, it is tightly coupled with GuardDuty and is a product-specific tool, even within the AWS ecosystem.
If GuardDuty doesn't detect an attack technique, you won't find it in here.

## [AWS CloudSaga](https://github.com/awslabs/aws-cloudsaga) by AWS

AWS CloudSaga has a few simulation scenarios (five [at the time of writing](https://github.com/awslabs/aws-cloudsaga/tree/e4f065a8bb7558af94768301f41f7679ea9baa8b)). Some of them are more focused around identifying vulnerable resources in your account (such as [`imds_reveal`](https://github.com/awslabs/aws-cloudsaga/blob/e4f065a8bb7558af94768301f41f7679ea9baa8b/cloudsaga/scenarios/imds_reveal.py) listing your EC2 instances without IMDSv2 enforced), while others are designed to simulate attacker behavior.

The attacker behavior implemented by AWS Cloud Saga emulates several stages of the attack lifecycle, while Stratus Red Team purposely attempts to stay as granular as possible (see: [Philosophy](https://stratus-red-team.cloud/attack-techniques/philosophy/)). As much as possible, Stratus Red Team techniques also reference real-world incidents or breaches.

Finally, AWS CloudSaga is by design specific to AWS, while Stratus Red Team supports AWS, Azure, GCP and even Kubernetes.

## [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs

> CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool. It allows you to hone your cloud cybersecurity skills by creating and completing several "capture-the-flag" style scenarios.

CloudGoat is focused on spinning up vulnerable AWS infrastructure, so that you can exploit it to find a flag through a complete exploitation chain.

Use CloudGoat to: practice your AWS offensive security and enumeration skills.

Use Stratus Red Team to: emulate adversary behavior in AWS to validate your threat detection.

## [DeRF](https://thederf.cloud/)

DeRF takes inspiration from Stratus Red Team and implements a subset of its attack techniques. DeRF works by deploying a set of Google Cloud Workflows that detonate attack techniques by calling cloud providers' API  (see [here](https://github.com/vectra-ai-research/derf/blob/main/attack-techniques/aws/execution/ec2-modify-user-data/attack.tf#L36) for a sample attack technique).

DerF is more extensible than Stratus Red Team, might be more suitable for a shared team usage. The barrier to entry to use Stratus Red Team is lower, since it's a single binary you can run from anywhere with access to a cloud environment with no setup required.

## [Cloud Katana](https://cloud-katana.com)

Cloud Katana is an attack simulation tool, similar to Stratus Red Team. It works by detonating attack techniques in Azure functions. Attack techniques are described using a [JSON schema](https://cloud-katana.com/learn/schema.html), making it more extensible than Stratus Red Team.

As of September 27 2023, Cloud Katana contains 3 built-in attack techniques, all for Azure, while Stratus Red Team ships with attack techniques for Azure, AWS, GCP and Kubernetes.
