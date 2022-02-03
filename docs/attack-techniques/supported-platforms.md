# Supported Platforms

## AWS

To use Stratus Red Team attack techniques against AWS, you need to be authenticated prior to running it. See: [Connecting to your cloud account](https://stratus-red-team.cloud/user-guide/getting-started/#connecting-to-your-cloud-account).

## Kubernetes

Stratus Red Team also supports [Kubernetes attack techniques](https://stratus-red-team.cloud/attack-techniques/kubernetes/). 
It does **not** create a Kubernetes cluster for you.
Instead, it assumes you're already authenticated against a test Kubernetes cluster with `kubectl` and uses your default context.

As a rule of thumb, Stratus Red Team detonates attack techniques against the cluster you see when running `kubectl cluster-info`.

Tested with: Minikube and AWS EKS.

## Future Support for Additional Platforms

We plan to add support for [Azure](https://github.com/DataDog/stratus-red-team/issues/52) or [GCP](https://github.com/DataDog/stratus-red-team/issues/53) in the future.
If you're interested, go upvote the corresponding issue!