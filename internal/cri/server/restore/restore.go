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
)

// Checkpoint is an opaque handle to checkpoint content and its (UNTRUSTED)
// metadata. In the wiring follow-up this is backed by the unpacked status.dump /
// config.dump / spec.dump; here only the fields the trust boundary needs are
// modeled.
type Checkpoint struct {
	// ImageRef is the user-specified checkpoint image or archive reference.
	ImageRef string
	// Annotations are the annotations recorded in the checkpoint (status.dump).
	// These are attacker-authored and MUST NOT be trusted; they are passed
	// through [SanitizeAnnotations] before reaching any container config.
	Annotations map[string]string
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
	Name() string
	Validate(ctx context.Context, c *Checkpoint) error
}

// Rebinder re-acquires a resource (device, network identity, credentials)
// through the normal allocation path at restore time, instead of replaying the
// state recorded in the checkpoint. Re-binding rather than replaying is both the
// correct behavior for migration/warm-start and the security boundary that stops
// a checkpoint from smuggling host resources.
type Rebinder interface {
	Name() string
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

// Restorer runs the restore pipeline. The actual CRIU restore is performed by
// the caller (CRImportCheckpoint) AFTER Prepare succeeds; Restorer owns only the
// trust + transform phases so they are testable in isolation and cannot be
// bypassed by a future code path that forgets to sanitize.
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

// Prepare runs validate -> sanitize -> rebind and returns the sanitized
// annotation set for the restored container. It performs no CRIU restore and no
// container creation; the caller does that only if Prepare returns no error.
func (r *Restorer) Prepare(ctx context.Context, c *Checkpoint, createAnnotations map[string]string, m SpecMutator) (*Result, error) {
	if c == nil {
		return nil, errors.New("restore: nil checkpoint")
	}

	// Phase 1 -- trust gate (before any host-side effect).
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

	// Phase 3 -- re-acquire resources through normal allocation paths.
	for _, rb := range r.rebinders {
		if err := rb.Rebind(ctx, c, m); err != nil {
			return nil, fmt.Errorf("restore: rebinder %q failed: %w", rb.Name(), err)
		}
	}

	return &Result{Annotations: anns, DroppedAnnotations: dropped}, nil
}
