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
	"slices"
	"testing"
)

func TestSanitizeAnnotationsFailClosed(t *testing.T) {
	// status.dump annotations: a mix of checkpoint-origin runtime-sink keys and
	// two allowlisted bookkeeping keys (one also set by the create request, one not).
	checkpoint := map[string]string{
		"cdi.k8s.io/gpu":                       "nvidia.com/gpu=0",   // checkpoint-origin CDI device
		"devices.nri.io/container.app":         "/dev/mem",           // checkpoint-origin NRI device-injector
		"containerd.io/restart.loguri":         "binary:///bin/true", // checkpoint-origin restart-monitor log URI
		"user.tenant/whatever":                 "x",                  // arbitrary tenant key
		"io.kubernetes.container.hash":         "checkpoint-hash",    // allowlisted, ALSO in create
		"io.kubernetes.container.restartCount": "2",                  // allowlisted, only in checkpoint
	}
	// Trusted, kubelet-issued create-request annotations.
	create := map[string]string{
		"io.kubernetes.container.hash": "create-hash",
		"io.kubernetes.pod.name":       "real-pod",
	}

	got, dropped := SanitizeAnnotations(checkpoint, create, DefaultAnnotationPolicy())

	// Every out-of-namespace/unknown checkpoint key must be dropped.
	for _, k := range []string{
		"cdi.k8s.io/gpu",
		"devices.nri.io/container.app",
		"containerd.io/restart.loguri",
		"user.tenant/whatever",
	} {
		if _, ok := got[k]; ok {
			t.Errorf("checkpoint-origin annotation %q survived sanitization", k)
		}
		if !slices.Contains(dropped, k) {
			t.Errorf("expected %q to be reported as dropped", k)
		}
	}

	// Create-request is authoritative on conflict: the hash stays at the kubelet's
	// current value, NOT the checkpoint's stale one (else restore looks like a restart).
	if got["io.kubernetes.container.hash"] != "create-hash" {
		t.Errorf("create-request hash must win on conflict, got %q", got["io.kubernetes.container.hash"])
	}
	// An allowlisted key absent from the create request is filled from the checkpoint.
	if got["io.kubernetes.container.restartCount"] != "2" {
		t.Errorf("allowlisted restartCount should fill from checkpoint, got %q", got["io.kubernetes.container.restartCount"])
	}
	// Trusted create-request keys are preserved.
	if got["io.kubernetes.pod.name"] != "real-pod" {
		t.Errorf("create-request annotation lost: got %q", got["io.kubernetes.pod.name"])
	}
	// Dropped list is sorted for stable audit logs.
	if !slices.IsSorted(dropped) {
		t.Errorf("dropped annotations should be sorted, got %v", dropped)
	}
}

func TestSanitizeAnnotationsEmptyPolicyDropsAll(t *testing.T) {
	checkpoint := map[string]string{"anything": "v", "io.kubernetes.container.hash": "h"}
	create := map[string]string{"keep": "me"}

	got, dropped := SanitizeAnnotations(checkpoint, create, AnnotationPolicy{})

	if len(got) != 1 || got["keep"] != "me" {
		t.Errorf("empty policy should keep only create-request annotations, got %v", got)
	}
	if len(dropped) != 2 {
		t.Errorf("expected both checkpoint keys dropped, got %v", dropped)
	}
}

func TestSanitizeAnnotationsNilMaps(t *testing.T) {
	got, dropped := SanitizeAnnotations(nil, nil, DefaultAnnotationPolicy())
	if len(got) != 0 || len(dropped) != 0 {
		t.Errorf("nil maps should yield empty result, got %v / %v", got, dropped)
	}
}

func TestAnnotationPolicyAllows(t *testing.T) {
	p := AnnotationPolicy{Allow: []string{
		"exact.key",
		"prefix.allowed/*",
		"*", // must NOT become allow-all
		"",  // must be ignored
	}}
	cases := map[string]bool{
		"exact.key":          true,
		"exact.keyX":         false, // exact, not prefix
		"prefix.allowed/foo": true,
		"prefix.allowed/":    true,
		"prefix.allowedX":    false, // does not start with "prefix.allowed/"
		"cdi.k8s.io/gpu":     false, // the bare "*" entry must not allow this
		"anything.at.all":    false,
	}
	for key, want := range cases {
		if got := p.allows(key); got != want {
			t.Errorf("allows(%q) = %v, want %v", key, got, want)
		}
	}
}

// fakeValidator and fakeRebinder model restore extension points.
type fakeValidator struct {
	name string
	err  error
}

func (f fakeValidator) Name() string                                { return f.name }
func (f fakeValidator) Validate(context.Context, *Checkpoint) error { return f.err }

type fakeRebinder struct {
	ran *bool
	err error
}

func (fakeRebinder) Name() string { return "fake" }
func (f fakeRebinder) Rebind(_ context.Context, _ *Checkpoint, _ SpecMutator) error {
	if f.ran != nil {
		*f.ran = true
	}
	return f.err
}

// spy SpecMutator (non-nil, no-op).
type spyMutator struct{}

func (spyMutator) RebindDevice(context.Context, string) error { return nil }

func TestRestorerPrepareSanitizes(t *testing.T) {
	r := New(DefaultPolicy())
	cp := &Checkpoint{Annotations: map[string]string{
		"cdi.k8s.io/x":                 "v",
		"io.kubernetes.container.hash": "h",
	}}
	res, err := r.Prepare(context.Background(), cp, map[string]string{"base": "1"})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, ok := res.Annotations["cdi.k8s.io/x"]; ok {
		t.Error("pipeline did not sanitize the checkpoint-origin CDI annotation")
	}
	if res.Annotations["base"] != "1" {
		t.Error("pipeline lost the create-request annotation")
	}
}

func TestRestorerRebindSpec(t *testing.T) {
	ran := false
	r := New(DefaultPolicy(), WithRebinder(fakeRebinder{ran: &ran}))
	if err := r.RebindSpec(context.Background(), &Checkpoint{}, spyMutator{}); err != nil {
		t.Fatalf("RebindSpec: %v", err)
	}
	if !ran {
		t.Error("rebinder was not invoked by RebindSpec")
	}
}

func TestRestorerRebindSpecNilMutator(t *testing.T) {
	r := New(DefaultPolicy(), WithRebinder(fakeRebinder{}))
	if err := r.RebindSpec(context.Background(), &Checkpoint{}, nil); err == nil {
		t.Fatal("expected error when a rebinder is registered but SpecMutator is nil")
	}
	// No rebinders -> nil mutator is fine.
	if err := New(DefaultPolicy()).RebindSpec(context.Background(), &Checkpoint{}, nil); err != nil {
		t.Fatalf("RebindSpec with no rebinders should not error: %v", err)
	}
}

func TestRestorerValidatorError(t *testing.T) {
	r := New(DefaultPolicy(), WithValidator(fakeValidator{name: "deny", err: errors.New("bad signature")}))
	if _, err := r.Prepare(context.Background(), &Checkpoint{}, nil); err == nil {
		t.Fatal("expected Prepare to abort when a validator rejects the checkpoint")
	}
}

func TestRestorerRebinderError(t *testing.T) {
	r := New(DefaultPolicy(), WithRebinder(fakeRebinder{err: errors.New("alloc failed")}))
	if err := r.RebindSpec(context.Background(), &Checkpoint{}, spyMutator{}); err == nil {
		t.Fatal("expected RebindSpec to surface a rebinder error")
	}
}

func TestRestorerRequireVerified(t *testing.T) {
	// RequireVerified with no validator -> error.
	r := New(Policy{Annotations: DefaultAnnotationPolicy(), RequireVerified: true})
	if _, err := r.Prepare(context.Background(), &Checkpoint{}, nil); err == nil {
		t.Fatal("expected error when RequireVerified is set but no validator is configured")
	}
	// RequireVerified with an accepting validator -> ok.
	r = New(Policy{Annotations: DefaultAnnotationPolicy(), RequireVerified: true},
		WithValidator(fakeValidator{name: "ok"}))
	if _, err := r.Prepare(context.Background(), &Checkpoint{}, nil); err != nil {
		t.Fatalf("expected success with an accepting validator: %v", err)
	}
}
