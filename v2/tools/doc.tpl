---
title: {{.Technique.FriendlyName}}
---

# {{.Technique.FriendlyName}}

{{ if .Technique.IsSlow }} <span class="smallcaps w3-badge w3-orange w3-round w3-text-sand" title="This attack technique might be slow to warm up or detonate">slow</span> {{ end }}
{{ if .Technique.IsIdempotent }} <span class="smallcaps w3-badge w3-blue w3-round w3-text-white" title="This attack technique can be detonated multiple times">idempotent</span> {{ end }}

Platform: {{FormatPlatformName .Technique.Platform}}

## MITRE ATT&CK Tactics

{{JoinTactics .Technique.MitreAttackTactics "\n- " "\n- "}}

## Description

{{.Technique.Description}}

## Instructions

```bash title="Detonate with Stratus Red Team"
stratus detonate {{.Technique.ID}}
```{{ if .Technique.Detection }}
## Detection

{{ .Technique.Detection }}

{{ end }}

{{ if .DetonationLogs }}
## Detonation logs <span class="smallcaps w3-badge w3-pink w3-round w3-text-sand" title="TODO">new</span>

The following CloudTrail events are generated when this technique is detonated[^1]:

{{range $event := .DetonationLogs.EventNames }}
- `{{ $event }}`
{{end}}

??? "View raw detonation logs"

    ```json hl_lines="{{range $i, $line := .DetonationLogs.EventNameLines}}{{if $i}} {{end}}{{$line}}{{end}}"

    {{ .DetonationLogs.RawLogs }}
    ```

[^1]: These logs have been gathered from a real detonation of this technique in a test environment using [Grimoire](https://github.com/DataDog/grimoire), and anonymized using [LogLicker](https://github.com/Permiso-io-tools/LogLicker).
{{ end }}