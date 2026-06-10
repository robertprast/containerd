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

// Package restore defines a first-class, security-bounded API surface for
// restoring containers from checkpoints, kept deliberately separate from the
// normal container-create path.
//
// # Why
//
// Today, restore is an implicit branch of CreateContainer: containerd detects a
// checkpoint-annotated image and re-emits a create request built from
// attacker-authored checkpoint metadata (status.dump / config.dump), feeding it
// back into the pipeline otherwise reserved for kubelet-validated input. That one
// decision turns untrusted archive bytes into trusted CRI inputs, which is the
// root cause behind the CDI annotation-smuggling class (and the same re-trust
// reaches other annotation-driven sinks: NRI plugins, snapshot id-map labels,
// the restart-monitor log URI, blockIO/RDT class selection).
//
// # Design (two phase)
//
// Phase 1 (this skeleton): draw the trust boundary explicitly. Checkpoint content
// is UNTRUSTED by default. A restore is a pipeline with three stages:
//
//		validate  -> sanitize -> rebind -> (CRIU restore, performed by the caller)
//
//	  - validate: gate the checkpoint before ANY host-side effect (signature /
//	    provenance / compatibility). Pluggable, like image verifiers.
//	  - sanitize: install only an explicit allowlist of checkpoint-origin
//	    annotations onto the restored container; everything else is dropped
//	    fail-closed (see [SanitizeAnnotations]). This subsumes the per-prefix
//	    denylist: a forgotten future sink fails CLOSED (restore drops the key)
//	    instead of OPEN (silent re-trust).
//	  - rebind: re-acquire devices / network / identity through the NORMAL
//	    allocation path (device-plugin / DRA / CNI / fresh SA token) instead of
//	    replaying checkpoint-recorded state (see [Rebinder]).
//
// Phase 2 (follow-up, public): promote this to a dedicated CRI/runtime Restore
// RPC so the orchestrator can declare intent and policy (preserve vs rebind
// network identity, device re-allocation strategy, trust posture), and so the
// same primitive can back live migration and warm-start ("restore many from one
// snapshot"). The unifying property is the same as the security fix:
// re-allocate and rebind instead of replay.
//
// This package is an RFC skeleton: the trust boundary ([SanitizeAnnotations]) is
// implemented and tested; the extension points ([Validator], [Rebinder]) and the
// pipeline ([Restorer]) are defined with no-op defaults. Wiring into
// CRImportCheckpoint is intentionally left to a follow-up so this change is
// additive and reviewable on its own.
package restore
