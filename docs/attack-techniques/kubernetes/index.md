# Kubernetes

This page contains the Stratus attack techniques for Kubernetes, grouped by MITRE ATT&CK Tactic.
Note that some Stratus attack techniques may correspond to more than a single ATT&CK Tactic.


## Credential Access

- [Dump All Secrets](./k8s.credential-access.dump-secrets.md)

- [Steal Pod Service Account Token](./k8s.credential-access.steal-serviceaccount-token.md)


## Persistence

- [Create Admin ClusterRole](./k8s.persistence.create-admin-clusterrole.md)

- [Create Client Certificate Credential](./k8s.persistence.create-client-certificate.md)

- [Create Long-Lived Token](./k8s.persistence.create-token.md)


## Privilege Escalation

- [Create Admin ClusterRole](./k8s.persistence.create-admin-clusterrole.md)

- [Container breakout via hostPath volume mount](./k8s.privilege-escalation.hostpath-volume.md)

- [Privilege escalation through node/proxy permissions](./k8s.privilege-escalation.nodes-proxy.md)

- [Run a Privileged Pod](./k8s.privilege-escalation.privileged-pod.md)

