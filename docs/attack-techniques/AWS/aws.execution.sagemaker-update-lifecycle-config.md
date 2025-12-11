---
title: Create/Update SageMaker Lifecycle Configuration for Privilege Escalation
---

# Create/Update SageMaker Lifecycle Configuration for Privilege Escalation

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 
 <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> 

Platform: AWS

## Mappings

- MITRE ATT&CK
    - Execution
  - Privilege Escalation



## Description


An attacker with permissions to stop, update, and start a SageMaker Notebook instance can escalate privileges by attaching a malicious lifecycle configuration script to a stopped instance. When the instance is restarted, this script executes automatically, allowing the attacker to exfiltrate the instance's IAM execution role credentials or perform actions with its elevated permissions.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a SageMaker Notebook Instance with an IAM Execution Role that possesses sensitive privileges (the victim role). 
- Create an Attacker IAM Identity with only the permissions to stop, update, and start the notebook and to inject a malicious lifecycle configuration script.

<span style="font-variant: small-caps;">Detonation</span>: 

- Update the lifecycle configuration script via a Stop-Update-Start API sequence
- Execute malicious code

References:

- https://www.plerion.com/blog/privilege-escalation-with-sagemaker-and-execution-roles


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate aws.execution.sagemaker-update-lifecycle-config
```
## Detection


Through CloudTrail's <code>UpdateNotebookInstance</code> events. 
You can also watch for suspicious sequences of <code>StopNotebookInstance</code> and <code>StopNotebookInstance</code> events correlated with <code>UpdateNotebookInstance</code> events. 


