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
// is UNTRUSTED by default. A restore applies these stages, at the TWO points in
// the flow where they actually fit (not one call):
//
//	[Restorer.Prepare]   (pre-create):  validate -> sanitize
//	[Restorer.RebindSpec] (spec build): rebind
//	(then the caller performs the CRIU restore)
//
//	  - validate: gate the checkpoint (signature / provenance / compatibility)
//	    before the restore commits persistent host-side effects (image pull, tag
//	    write). Pluggable, like image verifiers. Note: today's CRImportCheckpoint
//	    already unpacks the checkpoint to a temp mount before this point, so a
//	    stricter "verify before unpack" posture means moving the gate earlier --
//	    called out in the RFC, not assumed here.
//	  - sanitize: install only an explicit allowlist of checkpoint-origin
//	    annotations onto the restored container; create-request values are
//	    authoritative and everything not allowlisted is dropped fail-closed (see
//	    [SanitizeAnnotations]). This subsumes the per-prefix denylist: a forgotten
//	    future sink fails CLOSED (restore drops the key) instead of OPEN (silent
//	    re-trust).
//	  - rebind: during spec construction, re-acquire devices / network / identity
//	    through the NORMAL allocation path (device-plugin / DRA / CNI / fresh SA
//	    token) instead of replaying checkpoint-recorded state (see [Rebinder]).
//	    The OCI spec does not exist at Prepare time, which is why this is a
//	    separate call.
//
// Phase 2 (follow-up, public): promote this to a dedicated CRI/runtime Restore
// RPC so the orchestrator can declare intent and policy (preserve vs rebind
// network identity, device re-allocation strategy, trust posture), and so the
// same primitive can back live migration and warm-start ("restore many from one
// snapshot"). The unifying property is the same as the security fix:
// re-allocate and rebind instead of replay.
//
// Phase 1 is implemented and wired: CreateContainer gates restore behind the
// enable_checkpoint_restore config option (off by default, fail closed),
// CRImportCheckpoint runs [Restorer.Prepare] (with [NewMetadataValidator] and
// RequireVerified) before any persistent host-side effect, and createContainer
// invokes [Restorer.RebindSpec] after the OCI spec is built. [Validator] and
// [Rebinder] remain the extension points for signature/provenance verification
// and DRA/device-plugin re-binding.
package restore
