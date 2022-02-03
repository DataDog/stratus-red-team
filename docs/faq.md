# F.A.Q.

## What permissions do I need to run Stratus Red Team?

Stratus Red Team is supposed to be run against a sandbox cloud account or Kubernetes cluster. Consequently, we recommend using it with an administrator role.

If you don't have access to an administrator role but would still like to use Stratus Red Team, feel free to [open an issue](https://github.com/DataDog/stratus-red-team/issues/new/choose).

## How does Stratus Red Team persist state?

Stratus Red Team persists its state in `$HOME/.stratus-red-team`.

## How can I add my own attack techniques to Stratus Red Team?

Stratus Red Team is a self-contained Go binary. 
The implication is that you can't add attack techniques without contributing to its core, as Go cannot easily load code dynamically.
While Stratus Red Team may implement a plugin system in the future, we currently feel this would add substantial complexity for a limited value.

Note that you can define custom attack techniques when [using Stratus Red Team as a Go library](https://stratus-red-team.cloud/user-guide/programmatic-usage/).

## Why didn't you use Python?

While using Python would have made some things easier, we consider it is very hard to write solid software in Python, in particular due to the lack of typing.

In addition to that, the official Hashicorp Terraform wrapper ([tfexec](https://github.com/hashicorp/terraform-exec)) used by Stratus Red Team is written in Go. There is no solid, officially-supported wrapper for Python.

Finally, distributing Go binaries is much easier and leads to a better end-user experience.

## Can I use Stratus Red Team to detonate attack techniques against my own infrastructure?

- AWS: This is currently not supported. Stratus Red Team takes care of spinning up all the required infrastructure before detonating attack techniques. Allowing to "bring your own detonation infrastructure" is on the roadmap.
- 
- Kubernetes: Stratus Red Team does not create or destroy Kubernetes clusters for you. You point it at an existing Kubernetes cluster, and it will take care of creating any prerequisite Kubernetes resource required to detonate Kubernetes-specific attack techniques.