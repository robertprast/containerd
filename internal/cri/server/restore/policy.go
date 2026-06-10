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

import "strings"

// AnnotationPolicy controls which checkpoint-origin annotations are allowed to
// survive onto a restored container.
//
// The model is an allowlist, on purpose. A denylist (strip the annotation keys
// we currently know to be dangerous, e.g. "cdi.k8s.io/") fails OPEN: when a
// future feature adds a new annotation-driven sink and nobody remembers to
// extend the denylist, the checkpoint silently re-trusts it. An allowlist fails
// CLOSED: an unknown checkpoint annotation is dropped, and the only failure mode
// is that a legitimately-needed bookkeeping key was forgotten -- which surfaces
// loudly as a restore/round-trip regression in tests, not as a silent CVE.
type AnnotationPolicy struct {
	// Allow lists annotation keys restored from the checkpoint. Each entry is
	// either an exact key, or a prefix written with a trailing "*". Anything not
	// matched is dropped. Empty means: restore no annotations from the checkpoint.
	Allow []string
}

// DefaultAnnotationPolicy restores only the small set of Kubernetes bookkeeping
// annotations that the kubelet expects to round-trip through a restore, so it
// does not see the container as needing a restart. Everything else from the
// checkpoint (cdi.k8s.io/*, devices.nri.io/*, containerd.io/*, operator/tenant
// keys, ...) is dropped.
//
// Keep this list intentionally tiny and explicit. Adding an entry is a
// deliberate decision that the key is display/bookkeeping only and never reaches
// a host-affecting sink.
func DefaultAnnotationPolicy() AnnotationPolicy {
	return AnnotationPolicy{
		Allow: []string{
			"io.kubernetes.container.hash",
			"io.kubernetes.container.restartCount",
			"io.kubernetes.container.terminationMessagePath",
			"io.kubernetes.container.preStopHandler",
			"io.kubernetes.container.ports",
		},
	}
}

// allows reports whether key is permitted by the policy.
func (p AnnotationPolicy) allows(key string) bool {
	for _, pat := range p.Allow {
		if pat == key {
			return true
		}
		if pfx, ok := strings.CutSuffix(pat, "*"); ok && strings.HasPrefix(key, pfx) {
			return true
		}
	}
	return false
}

// SanitizeAnnotations computes the annotation set for a restored container.
//
// createRequest annotations are trusted (they came from the live, kubelet-issued
// CRI request) and form the base. From the checkpoint -- which is UNTRUSTED --
// only keys permitted by the policy are layered on top (so e.g. the container
// hash / restart count can round-trip). Every other checkpoint annotation is
// dropped and reported via the returned slice for logging/audit.
//
// This is the single chokepoint that protects every downstream consumer of the
// restored annotation map at once (CDI, NRI, blockIO/RDT, restart monitor, ...),
// rather than each sink defending itself.
func SanitizeAnnotations(checkpoint, createRequest map[string]string, p AnnotationPolicy) (result map[string]string, dropped []string) {
	result = make(map[string]string, len(createRequest))
	for k, v := range createRequest {
		result[k] = v
	}
	for k, v := range checkpoint {
		if p.allows(k) {
			result[k] = v
			continue
		}
		// Do not override a trusted create-request value with an untrusted one,
		// and do not introduce an untrusted key. Record it as dropped.
		dropped = append(dropped, k)
	}
	return result, dropped
}
