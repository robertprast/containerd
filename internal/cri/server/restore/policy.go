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
	"slices"
	"strings"
)

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

// DefaultAnnotationPolicy restores the kubelet's own annotation namespace
// (io.kubernetes.*) -- the bookkeeping/metadata the kubelet expects to round-trip
// through a restore so it does not see the container as needing a restart -- and
// drops everything else from the checkpoint. Crucially, every known
// runtime-affecting annotation sink lives OUTSIDE io.kubernetes.*:
//
//	cdi.k8s.io/*                            (CDI device injection)
//	devices.nri.io/*, mounts.nri.io/*       (NRI device/hook injector plugins)
//	containerd.io/*                          (restart-monitor log URI, gc refs)
//	blockio.resources.beta.kubernetes.io/*   (blockIO class)
//	rdt.resources.beta.kubernetes.io/*       (RDT class)
//
// so this allowlist closes the smuggling class while staying behavior-preserving
// for the kubelet's metadata.
//
// KNOWN COMPATIBILITY RISK (settle via integration test before relying on this):
// some legitimate, operator-facing features key off annotations that are NOT
// under io.kubernetes.* and are therefore dropped from the checkpoint:
//
//	blockio.resources.beta.kubernetes.io/*   (blockIO QoS class)
//	rdt.resources.beta.kubernetes.io/*       (RDT QoS class)
//	operator-configured ContainerAnnotations passthrough (arbitrary keys)
//
// This is only a regression if, on restore, the kubelet does NOT re-supply these
// on the (trusted) create request -- in which case the value would have to come
// from the checkpoint, and we now drop it. If the kubelet re-supplies them (the
// expected behavior, since restore is a fresh create reflecting current desired
// state) there is no regression and dropping the stale checkpoint copy is correct.
// Containerd source cannot determine the kubelet's behavior; an integration test
// must. If it turns out the kubelet does not re-supply blockIO/RDT, add those two
// prefixes here -- they are bounded class-selection sinks (the kubelet is trusted)
// and far lower risk than the device/hook sinks this allowlist exists to block.
//
// io.kubernetes.cri.* is preserved by the prefix match and is also re-created
// during spec build (DefaultCRIAnnotations), so it does not regress.
func DefaultAnnotationPolicy() AnnotationPolicy {
	return AnnotationPolicy{
		Allow: []string{
			"io.kubernetes.*",
		},
	}
}

// allows reports whether key is permitted by the policy.
func (p AnnotationPolicy) allows(key string) bool {
	for _, pat := range p.Allow {
		// Ignore "match everything" / empty entries entirely (including via the
		// exact-match branch): an allowlist must name what it permits, so a stray
		// "*" or "" can never allow a key -- not even the literal key "*".
		if pat == "" || pat == "*" {
			continue
		}
		if pat == key {
			return true
		}
		// Prefix entries end in "*".
		if pfx, ok := strings.CutSuffix(pat, "*"); ok && pfx != "" && strings.HasPrefix(key, pfx) {
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
		if !p.allows(k) {
			// Not on the allowlist: drop it (and record for audit).
			dropped = append(dropped, k)
			continue
		}
		if _, exists := result[k]; exists {
			// Create-request annotations are authoritative; an allowlisted
			// checkpoint key only fills a gap the create request did not set.
			// This keeps e.g. io.kubernetes.container.hash / restartCount at the
			// kubelet's current value (so the restore is not seen as a restart)
			// rather than the checkpoint's stale one -- never override trusted
			// with untrusted, even for allowlisted keys.
			continue
		}
		result[k] = v
	}
	// Stable order for audit logs (map iteration is randomized).
	slices.Sort(dropped)
	return result, dropped
}
