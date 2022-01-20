# F.A.Q.

## How can I add my own attack techniques to Stratus Red Team?

Stratus Red Team is a self-contained Go binary. 
The implication is that you can't add attack techniques without contributing to its core, as Go cannot easily load code dynamically.

## Why didn't you use Python?

While using Python would have made some things easier, we consider it is very hard to write solid software in Python, in particular due to the lack of typing.

In addition to that, the official Hashicorp Terraform wrapper ([tfexec](https://github.com/hashicorp/terraform-exec)) used by Stratus Red Team is written in Go. There is no solid, officially-supported wrapper for Python.

Finally, distributing Go binaries is much easier and leads to a better end-user experience. 