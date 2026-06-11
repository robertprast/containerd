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
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
)

// realKubeletContainerAnnotations is the set of annotations a real kubelet puts
// on a CRI *container* config -- all under io.kubernetes.* -- that must survive a
// restore so the kubelet does not see the container as changed.
var realKubeletContainerAnnotations = map[string]string{
	"io.kubernetes.container.hash":                     "a1b2c3",
	"io.kubernetes.container.restartCount":             "0",
	"io.kubernetes.container.terminationMessagePath":   "/dev/termination-log",
	"io.kubernetes.container.terminationMessagePolicy": "File",
	"io.kubernetes.container.preStopHandler":           "{}",
	"io.kubernetes.container.ports":                    "[{\"containerPort\":8080}]",
	"io.kubernetes.pod.name":                           "web-0",
	"io.kubernetes.pod.namespace":                      "prod",
	"io.kubernetes.pod.uid":                            "uid-123",
	"io.kubernetes.pod.terminationGracePeriod":         "30",
	"io.kubernetes.cri.container-type":                 "container",
	"io.kubernetes.cri.sandbox-id":                     "sb-abc",
	"io.kubernetes.cri.container-name":                 "web",
	"io.kubernetes.cri.image-name":                     "nginx:1.27",
}

// runtimeSinkAnnotations is the set of runtime-affecting annotation sinks that a
// checkpoint could carry; ALL must be dropped when sourced from the checkpoint.
var runtimeSinkAnnotations = map[string]string{
	"cdi.k8s.io/gpu":                           "nvidia.com/gpu=0",
	"cdi.k8s.io":                               "x",
	"devices.nri.io/container.app":             "/dev/mem",
	"mounts.nri.io/container.app":              "/:/host",
	"containerd.io/restart.loguri":             "binary:///bin/true",
	"containerd.io/restart.status":             "running",
	"containerd.io/gc.ref.content.x":           "sha256:dead",
	"blockio.resources.beta.kubernetes.io/pod": "highio",
	"rdt.resources.beta.kubernetes.io/pod":     "privileged",
	"io.microsoft.container.processisolation":  "true",
	"user.tenant/whatever":                     "x",
	"":                                         "emptykey",
	"io.kubernetesX.fake":                      "near-miss-prefix",
	"prefix.io.kubernetes.container.hash":      "suffix-not-prefix",
}

// TestRealKubeletCorpusRoundTrips: a real checkpointed container's kubelet
// annotations survive a restore unchanged when the create request did not also
// carry them (checkpoint fills the gaps), and out-of-namespace keys are dropped.
func TestRealKubeletCorpusRoundTrips(t *testing.T) {
	checkpoint := map[string]string{}
	for k, v := range realKubeletContainerAnnotations {
		checkpoint[k] = v
	}
	for k, v := range runtimeSinkAnnotations {
		checkpoint[k] = v
	}

	got, dropped := SanitizeAnnotations(checkpoint, nil, DefaultAnnotationPolicy())

	for k, want := range realKubeletContainerAnnotations {
		if got[k] != want {
			t.Errorf("legit kubelet annotation %q not preserved on restore: got %q want %q", k, got[k], want)
		}
	}
	for k := range runtimeSinkAnnotations {
		if k == "" {
			continue // empty key can't be set in a real map anyway
		}
		if _, ok := got[k]; ok {
			t.Errorf("runtime-sink annotation %q survived restore", k)
		}
		if !slices.Contains(dropped, k) {
			t.Errorf("runtime-sink annotation %q not reported as dropped", k)
		}
	}
}

// TestLegitRequestCDISurvivesCheckpointCDIDropped is the crux of correctness:
// a device legitimately requested by the CURRENT (kubelet) create request must
// survive, while a device carried by the checkpoint must be dropped. They can
// even share the cdi.k8s.io/ prefix.
func TestLegitRequestCDISurvivesCheckpointCDIDropped(t *testing.T) {
	create := map[string]string{
		"cdi.k8s.io/net": "vendor.com/net=eth0", // operator/kubelet asked for this NOW
	}
	checkpoint := map[string]string{
		"cdi.k8s.io/gpu": "example.com/gpu=all", // carried by the checkpoint
	}
	got, dropped := SanitizeAnnotations(checkpoint, create, DefaultAnnotationPolicy())

	if got["cdi.k8s.io/net"] != "vendor.com/net=eth0" {
		t.Errorf("legit create-request CDI device was lost: %v", got)
	}
	if _, ok := got["cdi.k8s.io/gpu"]; ok {
		t.Error("checkpoint-origin CDI device survived")
	}
	if !slices.Contains(dropped, "cdi.k8s.io/gpu") {
		t.Error("checkpoint-origin CDI not reported dropped")
	}
}

// TestConflictBothUnallowlisted: if the same non-allowlisted key is in BOTH maps,
// the trusted create value survives (never overridden) and the checkpoint copy is
// reported as dropped (its value did not win).
func TestConflictBothUnallowlisted(t *testing.T) {
	create := map[string]string{"cdi.k8s.io/x": "trusted"}
	checkpoint := map[string]string{"cdi.k8s.io/x": "from-checkpoint"}
	got, dropped := SanitizeAnnotations(checkpoint, create, DefaultAnnotationPolicy())
	if got["cdi.k8s.io/x"] != "trusted" {
		t.Errorf("trusted create value must win, got %q", got["cdi.k8s.io/x"])
	}
	if !slices.Contains(dropped, "cdi.k8s.io/x") {
		t.Error("checkpoint copy should be reported dropped even though the create key survives")
	}
}

// TestIdempotent: sanitizing an already-sanitized result with itself as the
// checkpoint changes nothing (no key oscillation).
func TestIdempotent(t *testing.T) {
	checkpoint := map[string]string{}
	for k, v := range realKubeletContainerAnnotations {
		checkpoint[k] = v
	}
	for k, v := range runtimeSinkAnnotations {
		if k != "" {
			checkpoint[k] = v
		}
	}
	once, _ := SanitizeAnnotations(checkpoint, nil, DefaultAnnotationPolicy())
	twice, _ := SanitizeAnnotations(once, once, DefaultAnnotationPolicy())
	if len(once) != len(twice) {
		t.Fatalf("not idempotent: once=%d twice=%d", len(once), len(twice))
	}
	for k, v := range once {
		if twice[k] != v {
			t.Errorf("idempotence broken for %q: %q vs %q", k, v, twice[k])
		}
	}
}

// TestLargeMapNoPanic: many keys, no panic, bounded behavior.
func TestLargeMapNoPanic(t *testing.T) {
	checkpoint := make(map[string]string, 10000)
	for i := 0; i < 10000; i++ {
		checkpoint[fmt.Sprintf("user.tenant/key-%d", i)] = "v"
	}
	checkpoint["io.kubernetes.container.hash"] = "keep"
	got, dropped := SanitizeAnnotations(checkpoint, nil, DefaultAnnotationPolicy())
	if got["io.kubernetes.container.hash"] != "keep" {
		t.Error("allowlisted key lost in large map")
	}
	if len(got) != 1 {
		t.Errorf("expected exactly the 1 allowlisted key kept, got %d", len(got))
	}
	if len(dropped) != 10000 {
		t.Errorf("expected 10000 dropped, got %d", len(dropped))
	}
}

// TestWeirdKeys: unicode, very long, value-with-newline, near-miss prefixes.
func TestWeirdKeys(t *testing.T) {
	long := "io.kubernetes." + strings.Repeat("x", 4096)
	checkpoint := map[string]string{
		"io.kubernetes.éclair":         "unicode-but-allowed-prefix", // starts with io.kubernetes.
		long:                           "long-allowed",
		"io.kubernetes":                "exact-namespace-no-dot", // NOT io.kubernetes.* (no trailing dot match)
		"IO.KUBERNETES.container.hash": "uppercase",              // case-sensitive: dropped
		"io.kubernetes.x\ny":           "value\nwith\nnewline",   // allowed prefix, odd value
	}
	got, dropped := SanitizeAnnotations(checkpoint, nil, DefaultAnnotationPolicy())
	if _, ok := got["io.kubernetes.éclair"]; !ok {
		t.Error("unicode key under io.kubernetes. should be allowed")
	}
	if _, ok := got[long]; !ok {
		t.Error("long key under io.kubernetes. should be allowed")
	}
	if _, ok := got["IO.KUBERNETES.container.hash"]; ok {
		t.Error("uppercase key must be dropped (case-sensitive)")
	}
	// "io.kubernetes" (no trailing dot) does NOT match prefix "io.kubernetes." -> dropped.
	if _, ok := got["io.kubernetes"]; ok {
		t.Error(`"io.kubernetes" (no dot) should not match the io.kubernetes.* prefix`)
	}
	_ = dropped
}

// TestSanitizeInvariants is a randomized property test asserting the four core
// invariants over many random create/checkpoint combinations.
func TestSanitizeInvariants(t *testing.T) {
	pool := []string{
		"io.kubernetes.container.hash", "io.kubernetes.cri.sandbox-id", "io.kubernetes.pod.uid",
		"cdi.k8s.io/gpu", "devices.nri.io/container.x", "containerd.io/restart.loguri",
		"blockio.resources.beta.kubernetes.io/pod", "rdt.resources.beta.kubernetes.io/pod",
		"user.tenant/a", "user.tenant/b", "io.microsoft.container.x",
	}
	pol := DefaultAnnotationPolicy()
	rng := rand.New(rand.NewSource(1))

	pick := func(tag string) map[string]string {
		m := map[string]string{}
		for _, k := range pool {
			if rng.Intn(2) == 0 {
				m[k] = tag + ":" + k
			}
		}
		return m
	}

	for iter := 0; iter < 5000; iter++ {
		create := pick("create")
		checkpoint := pick("ckpt")
		got, dropped := SanitizeAnnotations(checkpoint, create, pol)

		// INV1 -- no re-trust: every result key is from create, or an allowlisted checkpoint key.
		for k := range got {
			_, inCreate := create[k]
			_, inCkpt := checkpoint[k]
			if !inCreate && !(inCkpt && pol.allows(k)) {
				t.Fatalf("iter %d INV1 violated: key %q survived illegitimately", iter, k)
			}
		}
		// INV2 -- create authority: create values are never overridden.
		for k, v := range create {
			if got[k] != v {
				t.Fatalf("iter %d INV2 violated: create %q=%q but got %q", iter, k, v, got[k])
			}
		}
		// INV3 -- drop accounting: a non-allowlisted checkpoint key is reported dropped.
		for k := range checkpoint {
			if !pol.allows(k) && !slices.Contains(dropped, k) {
				t.Fatalf("iter %d INV3 violated: %q dropped but not reported", iter, k)
			}
		}
		// INV4 -- allowlisted fill: an allowlisted checkpoint key absent from create takes the checkpoint value.
		for k, v := range checkpoint {
			if pol.allows(k) {
				if _, inCreate := create[k]; !inCreate && got[k] != v {
					t.Fatalf("iter %d INV4 violated: allowlisted %q should fill %q, got %q", iter, k, v, got[k])
				}
			}
		}
	}
}

// FuzzSanitizeAllowlist fuzzes the sanitizer and asserts the allowlist invariant
// (every surviving key is from create or an allowlisted checkpoint key) and no
// panic for arbitrary keys/values.
func FuzzSanitizeAllowlist(f *testing.F) {
	f.Add("cdi.k8s.io/gpu", "v1", "io.kubernetes.container.hash", "v2")
	f.Add("io.kubernetes.*", "v", "containerd.io/restart.loguri", "binary:///bin/true")
	pol := DefaultAnnotationPolicy()
	f.Fuzz(func(t *testing.T, ck, cv, rk, rv string) {
		checkpoint := map[string]string{ck: cv}
		create := map[string]string{rk: rv}
		got, _ := SanitizeAnnotations(checkpoint, create, pol)
		for k := range got {
			_, inCreate := create[k]
			_, inCkpt := checkpoint[k]
			if !inCreate && !(inCkpt && pol.allows(k)) {
				t.Fatalf("allowlist invariant violated for surviving key %q", k)
			}
		}
	})
}

// FuzzAllowsNoPanic fuzzes the matcher with arbitrary patterns/keys.
func FuzzAllowsNoPanic(f *testing.F) {
	f.Add("io.kubernetes.*", "io.kubernetes.container.hash")
	f.Add("*", "anything")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pat, key string) {
		p := AnnotationPolicy{Allow: []string{pat}}
		_ = p.allows(key) // must not panic
		// bare "*" and "" must never allow-all
		if (pat == "*" || pat == "") && key != "" && p.allows(key) {
			t.Fatalf("pattern %q must not match %q", pat, key)
		}
	})
}
