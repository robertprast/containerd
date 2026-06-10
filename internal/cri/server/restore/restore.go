/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package restore

import (
	"context"
	"errors"
	"fmt"

	crmetadata "github.com/checkpoint-restore/checkpointctl/lib"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// Checkpoint is a handle to checkpoint content and its (UNTRUSTED) metadata,
// backed by the unpacked status.dump / config.dump / spec.dump. Every field
// here is authored by whoever built the checkpoint and MUST NOT reach a
// host-side decision without validation.
type Checkpoint struct {
	// ImageRef is the user-specified checkpoint image or archive reference.
	ImageRef string
	// Annotations are the annotations recorded in the checkpoint (status.dump).
	// These are attacker-authored and MUST NOT be trusted; they are passed
	// through [SanitizeAnnotations] before reaching any container config.
	Annotations map[string]string
	// Config is the checkpoint's config.dump metadata (base image refs,
	// recorded runtime, checkpoint timestamps). UNTRUSTED.
	Config *crmetadata.ContainerConfig
	// Spec is the checkpoint's spec.dump (the OCI spec of the checkpointed
	// container). UNTRUSTED: it reflects the policy of the original container
	// as asserted by the checkpoint author, never the policy of the restore.
	Spec *runtimespec.Spec
	// Status is the checkpoint's status.dump (the CRI container status at
	// checkpoint time). UNTRUSTED.
	Status *runtime.ContainerStatus
}

// SpecMutator is the (narrow) view of the in-construction OCI spec that a
// [Rebinder] is allowed to adjust at restore time. Kept as an interface so the
// skeleton does not depend on the full spec/CRI types; the wiring follow-up
// supplies a concrete adapter.
type SpecMutator interface {
	// RebindDevice re-acquires a device through the normal allocation path
	// (device-plugin / DRA) and adds it to the spec. Implementations MUST NOT
	// honor device requests sourced from checkpoint metadata.
	RebindDevice(ctx context.Context, claim string) error
}

// Validator gates a restore BEFORE any host-side effect (snapshot mount, tag
// write, log copy, spec build). A non-nil error aborts the restore. This is the
// place for checkpoint signature / provenance / host-compatibility checks, and
// is pluggable in the same spirit as image verifiers.
type Validator interface {
	// Name identifies the validator in error messages.
	Name() string
	// Validate inspects the checkpoint and returns a non-nil error to abort the
	// restore before any host-side effect. Implementations must not mutate c.
	Validate(ctx context.Context, c *Checkpoint) error
}

// Rebinder re-acquires a resource (device, network identity, credentials)
// through the normal allocation path at restore time, instead of replaying the
// state recorded in the checkpoint. Re-binding rather than replaying is both the
// correct behavior for migration/warm-start and the security boundary that stops
// a checkpoint from smuggling host resources.
type Rebinder interface {
	// Name identifies the rebinder in error messages.
	Name() string
	// Rebind re-acquires a resource and applies it to the spec under
	// construction via m, which is guaranteed non-nil by RebindSpec.
	Rebind(ctx context.Context, c *Checkpoint, m SpecMutator) error
}

// Policy is the trust + transform policy applied to a restore.
type Policy struct {
	// Annotations controls which checkpoint annotations survive (fail-closed).
	Annotations AnnotationPolicy
	// RequireVerified rejects a restore unless at least one Validator ran and
	// accepted the checkpoint. Off by default to preserve current behavior; an
	// operator opting into verified-only restore sets this true.
	RequireVerified bool
}

// DefaultPolicy returns the safe default: untrusted checkpoint, bookkeeping-only
// annotation allowlist, verification optional.
func DefaultPolicy() Policy {
	return Policy{Annotations: DefaultAnnotationPolicy()}
}

// Restorer owns the trust + transform phases of a restore, exposed at the two
// points in the flow where they actually apply: [Restorer.Prepare] (validate +
// annotation sanitize, before the container is built) and [Restorer.RebindSpec]
// (device/network/identity re-bind, during spec construction). The CRIU restore
// itself is performed by the caller (CRImportCheckpoint). Keeping these phases
// here makes them testable in isolation and hard to bypass.
type Restorer struct {
	policy     Policy
	validators []Validator
	rebinders  []Rebinder
}

// Option configures a Restorer.
type Option func(*Restorer)

// WithValidator registers a checkpoint validator (signature/provenance/compat).
func WithValidator(v Validator) Option {
	return func(r *Restorer) { r.validators = append(r.validators, v) }
}

// WithRebinder registers a resource rebinder (device/network/identity).
func WithRebinder(rb Rebinder) Option {
	return func(r *Restorer) { r.rebinders = append(r.rebinders, rb) }
}

// New builds a Restorer with the given policy and extension points.
func New(p Policy, opts ...Option) *Restorer {
	r := &Restorer{policy: p}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Result is the output of the trust + transform phases.
type Result struct {
	// Annotations is the sanitized annotation set to install on the restored
	// container (create-request base + allowlisted checkpoint keys).
	Annotations map[string]string
	// DroppedAnnotations lists checkpoint annotation keys denied by policy.
	// Callers should log these for audit (e.g. a denied cdi.k8s.io/* key is a
	// signal someone tried to smuggle a device request through restore).
	DroppedAnnotations []string
}

// Prepare runs the pre-create phases -- validate then sanitize -- and returns
// the sanitized annotation set for the restored container. It performs no CRIU
// restore and no container creation; the caller proceeds only if Prepare returns
// no error.
//
// Re-binding is deliberately NOT part of Prepare: the OCI spec does not exist at
// this point in the restore flow (annotations are settled before the container /
// spec is built). Device/network/identity re-binding happens later, during spec
// construction, via [Restorer.RebindSpec] -- two real call sites, not one.
func (r *Restorer) Prepare(ctx context.Context, c *Checkpoint, createAnnotations map[string]string) (*Result, error) {
	if c == nil {
		return nil, errors.New("restore: nil checkpoint")
	}

	// Phase 1 -- trust gate. Should run before the restore commits persistent
	// host-side effects (image pull, tag write).
	verified := false
	for _, v := range r.validators {
		if err := v.Validate(ctx, c); err != nil {
			return nil, fmt.Errorf("restore: validator %q rejected checkpoint: %w", v.Name(), err)
		}
		verified = true
	}
	if r.policy.RequireVerified && !verified {
		return nil, errors.New("restore: policy requires a verified checkpoint but no validator is configured")
	}

	// Phase 2 -- annotation trust boundary (fail-closed allowlist).
	anns, dropped := SanitizeAnnotations(c.Annotations, createAnnotations, r.policy.Annotations)

	return &Result{Annotations: anns, DroppedAnnotations: dropped}, nil
}

// RebindSpec runs the registered rebinders against the OCI spec under
// construction, re-acquiring devices/network/identity through normal allocation
// paths instead of replaying checkpoint-recorded state. It is invoked during
// spec build -- a separate, later point in the restore flow than [Restorer.Prepare].
// m must be non-nil.
func (r *Restorer) RebindSpec(ctx context.Context, c *Checkpoint, m SpecMutator) error {
	if c == nil {
		return errors.New("restore: nil checkpoint")
	}
	if m == nil && len(r.rebinders) > 0 {
		return errors.New("restore: RebindSpec requires a non-nil SpecMutator")
	}
	for _, rb := range r.rebinders {
		if err := rb.Rebind(ctx, c, m); err != nil {
			return fmt.Errorf("restore: rebinder %q failed: %w", rb.Name(), err)
		}
	}
	return nil
}
