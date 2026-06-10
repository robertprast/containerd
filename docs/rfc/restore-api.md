# RFC: A first-class Restore API

Status: **Draft / skeleton** — seeking direction, not merge.

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

## Approach: two phases

**Phase 1 (this PR — additive skeleton).** Make the trust boundary explicit and
fail-closed, without rewiring the hot path. New package
`internal/cri/server/restore`:

```
validate  ->  sanitize  ->  rebind  ->  (CRIU restore, performed by caller)
```

- **validate** — gate the checkpoint before any host-side effect (signature /
  provenance / host compatibility). Pluggable, like image verifiers.
- **sanitize** — `SanitizeAnnotations` installs only an explicit allowlist of
  checkpoint annotations (bookkeeping keys the kubelet round-trips); everything
  else is dropped. Allowlist, not denylist: a forgotten key fails *closed*
  (visible restore regression in tests) rather than *open* (silent re-trust → CVE).
  One chokepoint protects every downstream consumer at once.
- **rebind** — re-acquire devices / network / identity through the **normal
  allocation path** (device-plugin / DRA / CNI / fresh SA token) instead of
  replaying checkpoint-recorded state.

Implemented, unit-tested, **and wired**: the annotation trust boundary — the
manual `hash`/`restartCount` fixup in `CRImportCheckpoint` is replaced by
`restore.SanitizeAnnotations` with the `io.kubernetes.*` allowlist (every known
runtime-affecting sink — `cdi.k8s.io/`, `devices.nri.io/`, `containerd.io/`,
blockIO/RDT — lives outside that namespace, so it is dropped). Defined with no-op
defaults and **not** yet wired: the `Validator` / `Rebinder` extension points.

> Verification note: the `restore` package compiles and its tests pass (run in a
> standalone module). The one-line wiring edit in `CRImportCheckpoint` is
> syntax-checked but **not** build-verified in the authoring environment (its CRI
> package needs a newer Go toolchain than was available); confirm with
> `go build ./internal/cri/...` and the checkpoint integration test before trust.

**Deferred to phase 2, on purpose (real refactors, not blind edits):**

- **validate placement** — `CRImportCheckpoint` already unpacks the checkpoint to
  a temp mount before annotations are handled, so a "verify before unpack" posture
  means moving the gate earlier than the current annotation site.
- **rebind into spec** — the OCI spec is built *inside* `createContainer` →
  `buildContainerSpec`, after annotations are settled, so `RebindSpec` needs a
  `SpecMutator` threaded through the spec-build pipeline (a signature change).

**Phase 2 (follow-up, public).** Promote to a dedicated CRI/runtime Restore RPC so
the orchestrator declares intent + policy (preserve vs rebind network identity,
device re-allocation strategy, trust posture) rather than it leaking in via the
create path.

## Wired call site (annotations) + the deferred phases

What this PR wires into `CRImportCheckpoint` today, replacing the manual fixup:

```go
// originalAnnotations = containerStatus.GetAnnotations()  (UNTRUSTED)
sanitized, dropped := restore.SanitizeAnnotations(
    originalAnnotations, createAnnotations, restore.DefaultAnnotationPolicy())
for _, k := range dropped {
    log.G(ctx).Warnf("restore: dropping untrusted checkpoint annotation %q", k)
}
originalAnnotations = sanitized          // fail-closed; feeds meta.Config.Annotations
```

The full two-call-site shape the extension points are designed for (phase 2):

```go
r := restore.New(c.restorePolicy,
    restore.WithValidator(c.checkpointVerifier),   // gate before unpack (needs the gate moved earlier)
    restore.WithRebinder(c.deviceRebinder),        // re-allocate, don't replay
)
// pre-create:
res, err := r.Prepare(ctx, &restore.Checkpoint{ImageRef: inputImage, Annotations: originalAnnotations}, createAnnotations)
...
originalAnnotations = res.Annotations
// later, during buildContainerSpec (needs a SpecMutator threaded through):
err = r.RebindSpec(ctx, cp, specMutator)
```

## Why this is worth doing properly (beyond the CVE)

The boundary that closes the smuggling class — *re-allocate and rebind instead of
replay* — is the same primitive that unlocks:

- **Device re-binding** — restore re-acquires GPUs/accelerators through DRA/
  device-plugin (correct behavior *and* the security fix).
- **Live migration** — restore on a new node + rebind network/identity; the
  orchestrator expresses preserve-vs-rebind and a compatibility gate before
  committing downtime.
- **Warm starts** — restore from a pre-warmed snapshot, rebinding the
  unique-per-instance state (RNG, identity, secrets, connections) — the
  correctness requirement that also makes "restore many from one snapshot" safe.

One Restore API, three payoffs: it closes the security class, and the mechanism
that closes it is what makes warm-starts safe and live-migration correct.

## Compatibility blast radius (this is a behavior change)

Wiring `SanitizeAnnotations` into restore changes behavior: checkpoint annotations
outside `io.kubernetes.*` are now dropped. A source analysis of every annotation
consumer in the restore path classifies the impact:

| Annotation class | Source on restore | Verdict |
|---|---|---|
| `io.kubernetes.cri.*` | re-created in spec build (`DefaultCRIAnnotations`) + allowlisted | **safe** — no regression |
| `io.kubernetes.container.*`, `io.kubernetes.pod.*` | kubelet create request + allowlisted | **safe** |
| `restored` / `checkpointedAt` / `checkpointImage` | added by containerd *after* sanitize | **safe** |
| `cdi.k8s.io/*` (legit) | kubelet via create request or `CDIDevices` field | **safe if** kubelet re-supplies (likely; `CDIDevices` compensates) |
| `cdi.k8s.io/*`, `devices.nri.io/*`, `containerd.io/restart.*` (smuggled) | checkpoint only | **dropped — security win** |
| **`blockio.resources.beta.kubernetes.io/*`** | kubelet create request **or** checkpoint | **REGRESSION RISK** — dropped; QoS class lost if kubelet doesn't re-supply on restore |
| **`rdt.resources.beta.kubernetes.io/*`** | same | **REGRESSION RISK** — same |
| **operator `ContainerAnnotations` passthrough** (arbitrary keys) | kubelet create request | **REGRESSION RISK** — dropped if non-`io.kubernetes.*` and not re-supplied |

The three regression risks all reduce to **one unknown**: *does the kubelet
re-supply these on the restore create request?* Restore is a fresh `CreateContainer`
from the kubelet reflecting current desired state, so it *should* — but containerd
source can't prove it. The integration test below settles it; if the kubelet does
not re-supply blockIO/RDT, add those two (bounded, kubelet-trusted) prefixes to the
allowlist.

### Integration test checklist (run in a real kubelet+containerd node)
- [ ] checkpoint a container with `blockio.resources.beta.kubernetes.io/container.X`; restore; assert the blockIO class is applied (i.e. kubelet re-supplied it, or add the prefix).
- [ ] same for `rdt.resources.beta.kubernetes.io/container.X`.
- [ ] CDI: restore a container whose checkpoint requested a device; assert it is **not** injected unless the current request asked via `CDIDevices` / `cdi.k8s.io/*`.
- [ ] operator `container_annotations = ["custom.io/*"]`: checkpoint+restore; assert `custom.io/*` round-trips or document the limitation.
- [ ] smuggle: checkpoint with `cdi.k8s.io/`, `devices.nri.io/`, `containerd.io/restart.loguri`; assert all dropped (unit-covered; confirm end-to-end).

## Scope of this PR

- New `internal/cri/server/restore` package (+ tests), and the **annotation
  sanitization wired** into `CRImportCheckpoint` (replaces the manual
  hash/restartCount fixup). This is a behavior change on the restore path:
  non-`io.kubernetes.*` checkpoint annotations are now dropped.
- **Not** a CRI API change. `Validator` / `Rebinder` are defined but not wired
  (their phases need the refactors noted above).
- Verification: the package builds + tests pass; the CRImportCheckpoint edit is
  syntax-checked but not build-verified in the authoring env — needs
  `go build ./internal/cri/...` and the checkpoint integration test.
- Looking for agreement on the shape (fail-closed allowlist + the
  validate/rebind extension points) and on the allowlist breadth
  (`io.kubernetes.*` vs an explicit key list) before the public RPC work.
