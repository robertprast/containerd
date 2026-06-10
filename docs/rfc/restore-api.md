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

Implemented + unit-tested here: the annotation trust boundary. Defined with no-op
defaults: the `Validator` / `Rebinder` extension points and the `Restorer`
pipeline. Wiring into `CRImportCheckpoint` is intentionally deferred so this is
reviewable on its own.

**Phase 2 (follow-up, public).** Promote to a dedicated CRI/runtime Restore RPC so
the orchestrator declares intent + policy (preserve vs rebind network identity,
device re-allocation strategy, trust posture) rather than it leaking in via the
create path.

## Intended call site (sketch, not in this PR)

```go
// in CRImportCheckpoint, replacing the wholesale meta.Config.Annotations = ...
r := restore.New(c.restorePolicy,
    restore.WithValidator(c.checkpointVerifier),   // phase-1 trust gate
    restore.WithRebinder(c.deviceRebinder),        // re-allocate, don't replay
)
res, err := r.Prepare(ctx, &restore.Checkpoint{
    ImageRef:    inputImage,
    Annotations: containerStatus.GetAnnotations(), // UNTRUSTED
}, createAnnotations, specMutator)
if err != nil {
    return "", err
}
meta.Config.Annotations = res.Annotations          // sanitized, fail-closed
for _, k := range res.DroppedAnnotations {
    log.G(ctx).Warnf("restore: dropped untrusted checkpoint annotation %q", k)
}
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

## Scope of this PR

- New package + tests only. No behavior change to the existing restore path.
- Not wired in; not a CRI API change yet. Looking for agreement on the shape
  (pipeline + fail-closed allowlist + validate/rebind extension points) before the
  wiring and the public RPC work.
