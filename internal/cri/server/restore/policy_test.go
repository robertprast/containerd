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
	"slices"
	"testing"
)

func TestSanitizeAnnotationsFailClosed(t *testing.T) {
	// status.dump annotations: a mix of smuggling attempts and one allowlisted
	// bookkeeping key that should round-trip.
	checkpoint := map[string]string{
		"cdi.k8s.io/gpu":                       "nvidia.com/gpu=0", // smuggled CDI device
		"devices.nri.io/container.app":         "/dev/mem",         // smuggled NRI device-injector
		"containerd.io/restart.loguri":         "binary:///bin/sh", // smuggled restart-monitor RCE
		"user.tenant/whatever":                 "x",                // arbitrary tenant key
		"io.kubernetes.container.hash":         "new-hash",         // allowlisted: should win
		"io.kubernetes.container.restartCount": "2",                // allowlisted
	}
	// Trusted, kubelet-issued create-request annotations.
	create := map[string]string{
		"io.kubernetes.container.hash": "old-hash",
		"io.kubernetes.pod.name":       "victim",
	}

	got, dropped := SanitizeAnnotations(checkpoint, create, DefaultAnnotationPolicy())

	// Every dangerous/unknown checkpoint key must be dropped.
	for _, k := range []string{
		"cdi.k8s.io/gpu",
		"devices.nri.io/container.app",
		"containerd.io/restart.loguri",
		"user.tenant/whatever",
	} {
		if _, ok := got[k]; ok {
			t.Errorf("smuggled checkpoint annotation %q survived sanitization", k)
		}
		if !slices.Contains(dropped, k) {
			t.Errorf("expected %q to be reported as dropped", k)
		}
	}

	// Allowlisted bookkeeping keys round-trip, and the checkpoint value wins so
	// the kubelet does not see a spurious restart.
	if got["io.kubernetes.container.hash"] != "new-hash" {
		t.Errorf("allowlisted hash not restored from checkpoint: got %q", got["io.kubernetes.container.hash"])
	}
	if got["io.kubernetes.container.restartCount"] != "2" {
		t.Errorf("allowlisted restartCount not restored: got %q", got["io.kubernetes.container.restartCount"])
	}
	// Trusted create-request keys are preserved.
	if got["io.kubernetes.pod.name"] != "victim" {
		t.Errorf("create-request annotation lost: got %q", got["io.kubernetes.pod.name"])
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

// fakeRebinder records that it ran, modeling a device re-allocation through the
// normal path rather than replaying checkpoint state.
type fakeRebinder struct{ ran *bool }

func (fakeRebinder) Name() string { return "fake" }
func (f fakeRebinder) Rebind(_ context.Context, _ *Checkpoint, _ SpecMutator) error {
	*f.ran = true
	return nil
}

func TestRestorerPreparePipeline(t *testing.T) {
	ran := false
	r := New(DefaultPolicy(), WithRebinder(fakeRebinder{ran: &ran}))

	cp := &Checkpoint{Annotations: map[string]string{"cdi.k8s.io/x": "v", "io.kubernetes.container.hash": "h"}}
	res, err := r.Prepare(context.Background(), cp, map[string]string{"base": "1"}, nil)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if _, ok := res.Annotations["cdi.k8s.io/x"]; ok {
		t.Error("pipeline did not sanitize the smuggled CDI annotation")
	}
	if res.Annotations["base"] != "1" {
		t.Error("pipeline lost the create-request annotation")
	}
	if !ran {
		t.Error("rebinder was not run by the pipeline")
	}
}

func TestRestorerRequireVerified(t *testing.T) {
	r := New(Policy{Annotations: DefaultAnnotationPolicy(), RequireVerified: true})
	_, err := r.Prepare(context.Background(), &Checkpoint{}, nil, nil)
	if err == nil {
		t.Fatal("expected error when RequireVerified is set but no validator is configured")
	}
}
