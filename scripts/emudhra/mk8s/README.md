# Mitigate the eMudhra CA compromise on mk8s worker nodes

Nebius Managed Kubernetes supports only Ubuntu worker nodes. The mitigations in
this directory follow Canonical's recommendations for updating the Ubuntu
`ca-certificates` and `libnss3` packages.

New node infrastructure versions containing the fixes have been available for
upgrade in all production regions since 23 October at 00:00 UTC. They are also
selected by default for new node groups.

To determine whether a node group is affected, check
`NodeGroup.status.version`. The value has the format
`vX.Y.Z-nebius-node.I`, for example `v1.33.13-nebius-node.75`, where `I` is the
infrastructure version. Node groups with infrastructure versions below 78 are
affected.

Choose one of these three approaches according to the cluster's configuration
and usage:

1. **Upgrade affected node groups (recommended).** This is the most reliable,
   permanent mitigation.
2. **Add the patcher to cloud-init user data.** Use this less reliable option if
   applications cannot yet be adapted to the latest infrastructure version but
   nodes can be recreated.
3. **Apply the patcher DaemonSet.** Use this only as a temporary mitigation when
   node recreation is currently undesirable, then upgrade the node groups as
   soon as possible.

> **Important:** These approaches update and verify only
> the **node host trust stores**. They do not update CA bundles in workload
> images or language-specific trust stores. Patch those separately.

## Approach 1: upgrade node groups (recommended)

Upgrade each affected node group to the latest infrastructure version:

```bash
nebius mk8s node-group upgrade \
  --id <node-group-id> \
  --latest-infra-version
```

For images with preinstalled drivers—that is, node groups with
`spec.template.gpu_settings.drivers_preset` set—the upgrade may change GPU
package versions.

The upgrade recreates nodes according to `NodeGroup.status.strategy`. Adjust
this strategy before the rollout to suit the workload's availability
requirements. For example:

- set `max_unavailable` to `100%` and `drain_timeout` to `1s` to minimize the
  rollout duration at the cost of full downtime; or
- set `drain_timeout` to `0` to respect Pod Disruption Budgets, even if this
  prevents the rollout from progressing.

## Package and verification details for the patchers

The remaining two approaches use the supplied patchers. They check Ubuntu
22.04 and Ubuntu 24.04 hosts and change a host only when at least one installed
trust-store package is older than its applicable minimum:

| Ubuntu release | `ca-certificates` minimum | `libnss3` minimum |
| --- | --- | --- |
| 22.04 | `20260816ubuntu0.22.04.1` | `2:3.98-0ubuntu0.22.04.5` |
| 24.04 | `20260816ubuntu0.24.04.1` | `2:3.98-1ubuntu0.3` |

The patchers install the latest `ca-certificates` and `libnss3` versions
available from the host's configured APT repositories rather than pinning exact
package versions. Each package is evaluated independently, and only outdated
packages are passed to APT. There is no node infrastructure-version guard.

After checking or upgrading the packages, the patchers run the host's `curl`
against both eMudhra test endpoints:

- `https://dv-g3b-emudhra.we-have-a-problem.com/`
- `https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`

Both requests must fail with curl exit code 60 (certificate verification
failure). A successful request means the compromised chain is still trusted.
Other curl failures do not prove that the system trust store is safe and also
fail the check. The NSS mitigation is verified by requiring the fixed `libnss3`
package version from
[USN-8947-1](https://ubuntu.com/security/notices/USN-8947-1).

## Approach 2: cloud-init user data

Use [`cloud-init-user-data.yaml`](cloud-init-user-data.yaml) as the
`cloud_init_user_data` of a new node group or node template. If the node
template already has cloud-init configuration, merge the supplied file's
`write_files` and `runcmd` entries into that configuration instead of replacing
it.

> **Warning:** `cloud_init_user_data` is rollout-triggering node-template data.
> Changing it on an existing node group triggers a rolling replacement of all
> nodes in that group according to its deployment strategy; it is not applied
> in place. Plan for node draining, workload disruption, and any temporary
> capacity required by the rollout.

Update an existing node group with the CLI:

```bash
nebius mk8s node-group update \
  --id <node-group-id> \
  --template-cloud-init-user-data "$(</path/to/cloud-init-user-data.yaml)"
```

Alternatively, update and apply the Terraform definitions. For example,
Terraform can load the file with:

```hcl
cloud_init_user_data = file("${path.module}/cloud-init-user-data.yaml")
```

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

The containerd restart is attempted even when no package was updated. Unlike
the DaemonSet patcher, the user-data patcher does not wait for containerd to
remain active and does not retry a failed restart.

The script always exits successfully. An update, containerd restart,
connectivity, or verification failure therefore does not fail cloud-init or
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

## Approach 3: temporary DaemonSet

[`daemonset.yaml`](daemonset.yaml) schedules a pod on every Linux node,
including tainted nodes. It updates `ca-certificates` and `libnss3`, verifies
the result, and by default restarts containerd. Non-Ubuntu hosts and unsupported
Ubuntu releases are skipped.

This is a temporary mitigation. Upgrade to the latest infrastructure version
for a reliable, permanent fix, and remove the DaemonSet as soon as all node
groups have been upgraded.

> **Important:** Restarting containerd on a node with running pods may disrupt
> workloads. Leave restarts enabled at your discretion. This mitigation does
> not restart other processes or workloads that may have cached the compromised
> certificates.

### Containerd restart behavior

When the DaemonSet upgrades `ca-certificates`, it restarts containerd by
default after package-version and online verification succeed, so the
long-running process reloads the updated system CA store. Containerd uses Go's
TLS implementation and the system CA bundle; it does not use the NSS libraries.
A `libnss3`-only upgrade therefore does not restart containerd. If both packages
already meet their minimum versions, containerd is also not restarted.

Nebius node images with the fixed packages start containerd with the updated
files already present. Users who update packages independently remain
responsible for restarting affected services. Existing containers normally
continue running through a containerd restart, but CRI requests and image
operations can be interrupted briefly.

After each restart attempt, the patcher waits up to 60 seconds for containerd
and requires it to remain active for at least 10 seconds. It makes at most three
attempts per container run. If all attempts fail while containerd can still
launch containers, the pod remains unready and Kubernetes keeps recreating it
with backoff. A marker on the host preserves the pending restart across
patcher-container restarts, so the next attempt is not skipped merely because
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

### Resources and security

`daemonset.yaml` creates only the `emudhra-ca-certificates-patcher` DaemonSet in
`kube-system`. The privileged patcher container mounts the host root and uses
the host's APT, `dpkg`, and `curl` commands. It also joins the host PID and mount
namespaces with `nsenter` when invoking `systemctl`, adopting PID 1's root so
the host `systemctl` binary and systemd bus are used.

The Ubuntu patcher image is pinned to its multi-architecture image-index digest.
Even while the host trusts the compromised CA, a registry connection cannot
substitute a different manifest or layer without failing OCI digest validation.
An attacker can still prevent the image from being downloaded, so mirroring or
preloading the pinned image remains appropriate where availability is a
concern.

The DaemonSet's privileged access introduces additional security risk: anyone
with `exec` access to its pods can obtain root access to the Kubernetes nodes.
Remove it as soon as all node groups have been upgraded. 

### Prerequisites

Before applying the manifest, ensure that:

- the operator can create a DaemonSet in `kube-system`, or change the
  DaemonSet's namespace;
- nodes can pull `ubuntu:24.04`;
- eligible hosts can reach their configured Ubuntu APT repositories and both
  verification endpoints;
- `curl` is installed on the hosts (it should be included in Nebius node
  images); and
- unless the restart is disabled, the hosts use systemd (the default) to manage
  a `containerd` service.

### Apply

Save and review the DaemonSet file. Always select the target Kubernetes context
explicitly when applying it:

```bash
kubectl --context <context> apply \
  -f emudhra/mk8s/daemonset.yaml
```

Applying this manifest modifies outdated trust-store packages on eligible
hosts.

### Monitor and verify

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

Inspect a pod's patch result:

```bash
kubectl --context <context> \
  -n kube-system logs <pod-name> -c patcher
```

A running, Ready pod means the update and validation succeeded or the node did
not require an update. A successful or intentionally skipped pod remains
running and ready because DaemonSet pods cannot remain in the `Completed` state.
A failed package upgrade, verification, or enabled containerd restart causes
the patcher to restart, keeps the pod unready, and eventually puts it into
`CrashLoopBackOff`. Inspect the pod logs for details.

### Remove

Remove the DaemonSet as soon as all node groups have been upgraded:

```bash
kubectl --context <context> delete \
  --ignore-not-found \
  -f emudhra/mk8s/daemonset.yaml
```

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
