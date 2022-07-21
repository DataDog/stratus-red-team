# {{FormatPlatformName .Platform}}

This page contains the Stratus attack techniques for {{FormatPlatformName .Platform}}, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.

{{ range $tactic, $techniques := .TacticsMap }}
## {{ $tactic }}
{{ range $technique := $techniques }}
- [{{$technique.FriendlyName}}](./{{$technique.ID}}.md)
{{ end }}
{{ end }}