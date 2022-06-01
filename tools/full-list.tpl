---
hide:
  - toc
---

# List of all Attack Techniques

This page contains the list of all Stratus Attack Techniques.

| Name   | Platform | MITRE ATT&CK Tactics |
| :----: | :------: | :------------------: |
{{ range $technique := . }}| [{{ $technique.FriendlyName }}](./{{ $technique.Platform }}/{{ $technique.ID }}.md) | [{{FormatPlatformName $technique.Platform }}](./{{ $technique.Platform }}/index.md) | {{ JoinTactics $technique.MitreAttackTactics "" ", " }} |
{{ end }}