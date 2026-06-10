# RFC: A first-class Restore API

Status: **Draft — phase 1 implemented and wired** — seeking direction on phase 2.

## Problem

Restore is currently an implicit branch of `CreateContainer`: containerd detects a
checkpoint-annotated image (`checkIfCheckpointOCIImage`) and `CRImportCheckpoint`
re-emits a create request built from attacker-authored checkpoint metadata
(`status.dump` / `config.dump`), feeding it back into the pipeline otherwise
reserved for kubelet-validated input.

That one decision turns untrusted archive bytes into trusted CRI inputs. It is the
root cause behind the CDI annotation-smuggling advisory, and the *same* re-trust
reaches other annotation-driven sinks — NRI plugins, snapshot id-map labels, the
restart-monitor log URI, blockIO/RDT class selection. Each per-sink fix (e.g. a
`cdi.k8s.io/` denylist) closes one instance and **fails open** the next time a
feature adds an annotation-driven sink and nobody updates the list.

## Principles (P1–P5)

- **P1. Checkpoint content is untrusted tenant input**, on par with image bytes.
  No value embedded in a checkpoint reaches a host-side decision without the same
  validation a fresh `CreateContainer` applies to untrusted input.
- **P2. Policy comes from the live request, not the checkpoint.** Runtime policy
  (annotations, identity, image identity, mounts, labels, log paths) is re-derived
  from the kubelet's actual `CreateContainerRequest`. The checkpoint supplies the
  process memory image and nothing that sets policy.
- **P3. Restore is explicit and gated, not "run an image".** A proper design makes
  restore an opt-in operation the operator/orchestrator authorizes.
- **P4. Separate the two trust domains in the artifact.** The CRIU memory image
  (needed to restore) and the metadata/config (policy) are conflated today in one
  OCI image the tenant authors wholesale.
- **P5. Fail closed.** If a checkpoint asserts policy that does not match the live
  request, reject the restore rather than honoring the checkpoint's version.

## Phase 1 (this PR): trust boundary, implemented and wired

```
gate (config opt-in)  ->  validate  ->  sanitize  ->  rebind  ->  CRIU restore
```

All of the following is implemented and wired in this PR:

- **gate (P3/P5)** — `enable_checkpoint_restore` (CRI runtime config, default
  `false`). `CreateContainer` rejects checkpoint images/archives unless the
  operator opted in. Restore stops being silently tenant-reachable; the
  forensic-checkpoint side (`CheckpointContainer`) is unaffected.
- **validate (P1)** — `Restorer.Prepare` runs registered `Validator`s before the
  restore commits persistent host-side effects (base-image pull, tag write into
  the shared image store). The built-in `NewMetadataValidator` checks the
  checkpoint's structure and base-image references fail-closed; the policy is
  wired with `RequireVerified: true`. Signature/provenance validators layer on
  top, in the same spirit as image verifiers.
- **sanitize (P1/P2/P5)** — `SanitizeAnnotations` installs only an explicit
  allowlist of checkpoint annotations (`io.kubernetes.*` bookkeeping); the live
  request is authoritative, everything else is dropped (and logged). Allowlist,
  not denylist: a forgotten key fails *closed* (visible restore regression in
  tests) rather than *open* (silent re-trust → CVE). One chokepoint protects every
  downstream consumer (CDI, NRI, blockIO/RDT, restart monitor) at once.
- **rebind (P2/P4)** — `Restorer.RebindSpec` runs during `createContainer` spec
  build, after `buildContainerSpec`, so registered `Rebinder`s re-acquire
  devices/network/identity through normal allocation paths instead of replaying
  checkpoint state. No rebinders are registered by default (no-op); a failing
  rebinder aborts the restore.
- **target sandbox comes from the live request (P2)** — the old fallback that let
  the checkpoint's `spec.dump` choose the sandbox to restore into is removed;
  an empty live sandbox ID is now an error.

Drive-by fixes on the restore path, found while drawing the boundary:

- restored containers were built with `containerName = "containerd"` (the
  package-level version const captured by accident) instead of the live request's
  container name — mislabeling `io.kubernetes.cri.container-name` and blockIO/RDT
  class lookups for every restore;
- image-defined env vars were duplicated on restore (`imageConfig.Env` appended to
  itself).

## Phase 2 (follow-up, public)

Promote to a dedicated CRI/runtime Restore RPC so the orchestrator declares intent
and policy (preserve vs rebind network identity, device re-allocation strategy,
trust posture) rather than it leaking in via the create path. Needs a KEP in
SIG-Node: nothing in the CRI contract says "a checkpoint restore happens inside
CreateContainer" today. Phase 2 should also split the artifact (P4): CRIU memory
image vs policy metadata as separately-trusted objects, and decide
"verify-before-unpack" (today metadata must be unpacked to a temp mount before it
can be validated at all).

## Why this is worth doing properly (beyond the CVE)

The boundary that closes the smuggling class — *re-allocate and rebind instead of
replay* — is the same primitive that unlocks:

- **Device re-binding** — restore re-acquires GPUs/accelerators through DRA/
  device-plugin (correct behavior *and* the security fix).
- **Live migration** — restore on a new node + rebind network/identity; the
  orchestrator expresses preserve-vs-rebind and a compatibility gate before
  committing downtime.
- **Warm starts** — restore from a pre-warmed snapshot, rebinding the
  unique-per-instance state (RNG, identity, secrets, connections).

One Restore API, three payoffs.

## Compatibility blast radius (behavior changes)

1. **Restore is now opt-in** (`enable_checkpoint_restore = false` by default).
   Operators using restore-from-checkpoint must set the flag. Fail closed is the
   point: the implicit path is the vulnerability class.
2. **Checkpoint annotations outside `io.kubernetes.*` are dropped.** Source
   analysis of every annotation consumer on the restore path:

| Annotation class | Source on restore | Verdict |
|---|---|---|
| `io.kubernetes.cri.*` | re-created in spec build (`DefaultCRIAnnotations`) + allowlisted | **safe** |
| `io.kubernetes.container.*`, `io.kubernetes.pod.*` | kubelet create request + allowlisted | **safe** |
| `restored` / `checkpointedAt` / `checkpointImage` | added by containerd *after* sanitize | **safe** |
| `cdi.k8s.io/*` (legit) | kubelet via create request or `CDIDevices` field | **safe if** kubelet re-supplies (likely; `CDIDevices` compensates) |
| `cdi.k8s.io/*`, `devices.nri.io/*`, `containerd.io/restart.*` (smuggled) | checkpoint only | **dropped — security win** |
| `blockio.resources.beta.kubernetes.io/*` | kubelet create request **or** checkpoint | **regression risk** — dropped; QoS class lost if kubelet doesn't re-supply |
| `rdt.resources.beta.kubernetes.io/*` | same | **regression risk** — same |
| operator `ContainerAnnotations` passthrough | kubelet create request | **regression risk** — dropped if non-`io.kubernetes.*` and not re-supplied |

The regression risks reduce to one unknown: *does the kubelet re-supply these on
the restore create request?* Restore is a fresh `CreateContainer` reflecting
current desired state, so it should — the integration checklist below settles it.
If the kubelet does not re-supply blockIO/RDT, add those two (bounded,
kubelet-trusted) prefixes to the allowlist.

### Integration test checklist (real kubelet + containerd node)
- [ ] restore with `enable_checkpoint_restore` unset → CreateContainer fails with the gate error; set → restore succeeds.
- [ ] checkpoint with `blockio.resources.beta.kubernetes.io/container.X`; restore; assert the blockIO class is applied (or add the prefix).
- [ ] same for `rdt.resources.beta.kubernetes.io/container.X`.
- [ ] CDI: restore a checkpoint that requested a device; assert it is **not** injected unless the live request asked via `CDIDevices` / `cdi.k8s.io/*`.
- [ ] operator `container_annotations = ["custom.io/*"]`: checkpoint+restore; assert round-trip or document the limitation.
- [ ] smuggle: checkpoint with `cdi.k8s.io/`, `devices.nri.io/`, `containerd.io/restart.loguri`; assert all dropped end-to-end.

## Scope of this PR

- `internal/cri/server/restore` package (+ tests): policy, sanitizer, `Validator`
  / `Rebinder` extension points, built-in metadata validator.
- Wiring: gate in `CreateContainer`; `Restorer.Prepare` in `CRImportCheckpoint`
  before host-side effects; `RebindSpec` in `createContainer` after spec build;
  live-request-only sandbox targeting.
- Config: `enable_checkpoint_restore` (default `false`) + docs.
- **Not** a CRI API change; phase 2 (public Restore RPC, artifact split) is the
  follow-up this RFC seeks direction on.
