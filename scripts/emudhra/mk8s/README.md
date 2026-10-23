# Patch the eMudhra CA compromise on mk8s worker nodes

This ad hoc provides two ways to upgrade the Ubuntu `ca-certificates` and
`libnss3` packages and verify that the resulting host trust stores contain the
eMudhra compromise mitigations:

- `daemonset.yaml` patches eligible existing Kubernetes nodes;
- `cloud-init-user-data.yaml` patches a node during creation through user data.

IMPORTANT: This updates and verifies only the **node host trust stores**. It does not
update CA bundles contained in workload images. Those images and
language-specific trust stores must be patched separately.

## DaemonSet

The DaemonSet schedules a pod on every Linux node, including tainted nodes. It
checks Ubuntu 22.04 and Ubuntu 24.04 hosts and changes a host only when at least
one installed trust-store package is older than its applicable minimum:

| Ubuntu release | `ca-certificates` minimum | `libnss3` minimum |
| --- | --- | --- |
| 22.04 | `20260816ubuntu0.22.04.1` | `2:3.98-0ubuntu0.22.04.5` |
| 24.04 | `20260816ubuntu0.24.04.1` | `2:3.98-1ubuntu0.3` |

The patcher installs the latest `ca-certificates` and `libnss3` versions
available from the host's configured APT repositories rather than pinning exact
package versions. Each package is evaluated independently and only outdated
packages are passed to APT. Non-Ubuntu hosts and unsupported Ubuntu releases are
skipped. There is no node infra-version guard.

After checking or upgrading the packages, the patcher runs the host's `curl`
against both eMudhra test endpoints:

- `https://dv-g3b-emudhra.we-have-a-problem.com/`
- `https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`

Both requests must fail with curl exit code 60 (certificate verification
failure). A successful request means the compromised chain is still trusted;
other curl failures do not prove that the system trust store is safe and also
fail the check. The NSS mitigation is verified by requiring the fixed `libnss3`
package version from
[USN-8947-1](https://ubuntu.com/security/notices/USN-8947-1).

### Containerd restart

IMPORTANT: Restart of the containerd on a node with running pods 
may disrupt workloads, even though it shouldn't. 
Leave restarts enabled at your own discretion.

When the DaemonSet upgrades `ca-certificates`, it restarts containerd by
default after package-version and online verification succeed, so the
long-running process reloads the updated system CA store. Containerd uses Go's
TLS implementation and the system CA bundle; it does not use the NSS libraries.
A `libnss3`-only upgrade therefore does not restart containerd. If both packages
already meet their minimum versions, containerd is also not restarted.

Nebius node images with the fixed packages start containerd with the updated
files already present; users who update packages independently remain
responsible for restarting affected services.

Existing containers normally continue running through a containerd restart,
but CRI requests and image operations can be interrupted briefly.

After each restart attempt, the patcher waits up to 60 seconds for containerd
and requires it to remain active for at least 10 seconds. It makes at most three
attempts per container run. If all attempts fail while containerd is still able
to launch containers, the pod remains unready and Kubernetes keeps recreating
it with backoff. A marker on the host preserves the pending restart across
patcher-container restarts, so the next attempt is not skipped just because
package versions are already current. The marker is removed only after the
restart command succeeds and containerd is stable, or the restart is explicitly
disabled.

These retries cannot guarantee recovery from a containerd startup failure. If
containerd cannot start, the existing patcher container can make its remaining
in-process attempts, but the node cannot create another patcher pod after that
container exits. In that state, rely on node auto-repair to recover or replace
the unhealthy node.

The restart after a `ca-certificates` upgrade is opt-out. To skip it, change the
patcher environment variable in `daemonset.yaml` before applying the manifest:

```yaml
env:
  - name: RESTART_CONTAINERD
    value: "false"
```

Accepted false values are `false`, `0`, and `no`. An invalid value or a failed
restart keeps the pod unready.

### Resources

`daemonset.yaml` creates only the
`emudhra-ca-certificates-patcher` DaemonSet in `kube-system`. 
The privileged patcher container mounts the host root and uses the host's APT,
`dpkg`, and `curl` commands. It also joins the host PID and mount namespaces with
`nsenter` when invoking `systemctl`, adopting PID 1's root so the host
`systemctl` binary and systemd bus are used.

The Ubuntu patcher image is pinned to its multi-architecture image-index digest.
Even while the host trusts the compromised CA, a registry connection cannot
substitute a different manifest or layer without failing OCI digest validation.
An attacker can still prevent the image from being downloaded, so mirroring or
preloading the pinned image remains appropriate where availability is a
concern.

### Prerequisites

Before applying the manifest, ensure that:

- the operator can create a DaemonSet in `kube-system` or just change namespace of the DaemonSet;
- nodes can pull `ubuntu:24.04`;
- eligible hosts can reach their configured Ubuntu APT repositories and the two
  verification endpoints; and
- `curl` is installed on the hosts, should be shipped with Nebius node images; and
- unless the restart is disabled, the hosts use systemd(default behaviour) to manage a
  `containerd` service.

### Apply the DaemonSet

Always select the target Kubernetes context explicitly:

```bash
kubectl --context <context> apply \
  -f adhoc/NEBINC-2586_upgrade-ca-certificates/daemonset.yaml
```

Applying this manifest modifies outdated trust-store packages on eligible
hosts.

### Monitor

Wait for every DaemonSet pod to finish its check and become ready:

```bash
kubectl --context <context> \
  -n kube-system rollout status daemonset/emudhra-ca-certificates-patcher
```

List the pods and their assigned nodes:

```bash
kubectl --context <context> \
  -n kube-system get pods \
  -l app.kubernetes.io/name=emudhra-ca-certificates-patcher \
  -o wide
```

Inspect the patch result for a pod:

```bash
kubectl --context <context> \
  -n kube-system logs <pod-name> -c patcher
```

A successful or intentionally skipped pod remains running and ready. The
container sleeps after completion because DaemonSet pods cannot remain in the
`Completed` state. A failed package upgrade, verification, or enabled
containerd restart causes the patcher to restart and keeps the pod unready.

### Remove

IMPORTANT: It's required to remove this DaemonSet as soon as you updated all your nodes,
because it adds additional security risks because of its privileged access- anyone with `exec` privilege to the DS pods
can obtain root permission on the k8s nodes.

After all nodes have been checked, remove the DaemonSet:

```bash
kubectl --context <context> delete \
  --ignore-not-found \
  -f adhoc/NEBINC-2586_upgrade-ca-certificates/daemonset.yaml
```
## Update nodes with user data

> **Warning:** `cloud_init_user_data` is rollout-triggering node-template data.
> Changing it on an existing node group triggers a rolling replacement of all
> nodes in that group, according to its deployment strategy. The change is not
> applied in place. Plan for node draining, workload disruption, and any
> temporary capacity required by the rollout.

Use `cloud-init-user-data.yaml` as the `cloud_init_user_data` of a new node group
or node template. For example, Terraform configuration can load it with:

```hcl
cloud_init_user_data = file("${path.module}/cloud-init-user-data.yaml")
```

If the node template already has cloud-init configuration, merge the file's
`write_files` and `runcmd` entries into that configuration instead of replacing
it.

On every node created with it, the script:

1. checks `ca-certificates` and `libnss3` independently and updates only the
   packages below their minimum versions, using the latest versions available
   from the node's configured APT repositories;
2. rebuilds the host CA trust store when `ca-certificates` is updated;
3. restarts containerd once, unconditionally, so it reloads the current system
   CA store;
4. requires both package versions to contain the applicable fixes;
5. checks both eMudhra test endpoints; and
6. records whether the package update, containerd restart, version checks, and
   online verification succeeded.

IMPORTANT: The containerd restart is attempted even when no package was updated. Unlike
its DaemonSet counterpart, the user-data patcher does not wait for containerd
to remain active and does not retry a failed restart. 

IMPORTANT: The script always exits successfully, so an update, containerd restart, 
connectivity, or verification failure does not fail cloud-init or 
block node startup. Inspect the result in any of these locations on the node:

- `/var/log/emudhra-ca-certificates-patcher.log`;
- `/var/lib/emudhra-ca-certificates-patcher/status`;
- `/var/log/cloud-init-output.log`; or
- journald entries tagged `emudhra-ca-certificates-patcher`.

A fully successful status contains:

```text
update_status=success
trust_store_version_status=success
verification_status=success
containerd_restart_status=success
endpoint_dv_g3b_emudhra=rejected
endpoint_dv_g3b_aaa_emudhra=rejected
```

`update_status=not-needed` is also successful when both packages already meet
their minimum versions and APT is intentionally skipped.

## License

Copyright 2026 Nebius B.V.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

