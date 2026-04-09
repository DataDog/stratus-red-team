---
title: Execute Commands on GCE Instances via OS Config Agent
---

# Execute Commands on GCE Instances via OS Config Agent

 <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> 


Platform: GCP

## Mappings

- MITRE ATT&CK
    - Execution



## Description


Executes an arbitrary shell command on GCE instances by creating an OS Config
<code>OSPolicyAssignment</code>. The OS Config agent, which is pre-installed and
enabled on modern GCP images, polls for policy assignments and executes the
configured commands with root privileges. An attacker with
<code>osconfig.osPolicyAssignments.create</code> permission can abuse this
mechanism to achieve code execution on any instance in the project without
needing SSH access.

This is the GCP equivalent of AWS Systems Manager <code>SendCommand</code>.

<span style="font-variant: small-caps;">Warm-up</span>:

- Create a GCE instance (<code>e2-micro</code>, Debian 11) with the OS Config agent
  enabled via instance metadata (<code>enable-osconfig=TRUE</code>)

<span style="font-variant: small-caps;">Detonation</span>:

- Create an <code>OSPolicyAssignment</code> targeting instances labelled
  <code>stratus-red-team=true</code> that runs a shell command writing system
  information to <code>/tmp/stratus-output.txt</code>

Revert:

- Delete the <code>OSPolicyAssignment</code>

References:

- https://cloud.google.com/compute/docs/os-configuration-management
- https://cloud.google.com/compute/docs/osconfig/rest/v1/projects.locations.osPolicyAssignments
- https://blog.raphael.karger.is/articles/2022-08/GCP-OS-Patching


## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate gcp.execution.os-config-run-command
```
## Detection


<b>Note:</b> GCP does not emit Admin Activity audit logs for the OS Config API
(<code>osconfig.googleapis.com</code>). <code>CreateOSPolicyAssignment</code> events
are only logged if Data Access audit logging is explicitly enabled for
<code>osconfig.googleapis.com</code> with log type <code>DATA_WRITE</code>, which is
not enabled by default.

When Data Access logging is enabled, identify when an <code>OSPolicyAssignment</code>
is created or modified by monitoring for
<code>google.cloud.osconfig.v1.OsConfigZonalService.CreateOSPolicyAssignment</code>
and <code>google.cloud.osconfig.v1.OsConfigZonalService.UpdateOSPolicyAssignment</code>
events. Alert on assignments whose policies include <code>Exec</code> resources with
<code>ENFORCEMENT</code> mode, especially when the instance filter targets a broad set
of instances.


