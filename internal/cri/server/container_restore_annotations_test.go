//go:build linux

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

package server

import (
	"testing"

	"github.com/containerd/containerd/v2/internal/cri/server/restore"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	"tags.cncf.io/container-device-interface/pkg/cdi"
)

// These tests exercise the exact sanitize step CRImportCheckpoint performs
// (restore.SanitizeAnnotations over the checkpoint status.dump annotations) and
// feed the result into the REAL downstream sink (cdi.ParseAnnotations, the same
// call WithCDI makes at internal/cri/opts/spec_linux.go). They are the regression
// guard for the wiring: a smuggled checkpoint device must produce zero CDI device
// requests after sanitization, while a device the live create request asked for
// must survive.

func sanitizeLikeRestore(t *testing.T, statusAnnotations, createAnnotations map[string]string) map[string]string {
	t.Helper()
	status := &runtime.ContainerStatus{Annotations: statusAnnotations}
	got, _ := restore.SanitizeAnnotations(status.GetAnnotations(), createAnnotations, restore.DefaultAnnotationPolicy())
	return got
}

// A cdi.k8s.io/* device smuggled in the checkpoint must reach the CDI parser as
// nothing.
func TestRestoreSanitizeBlocksSmuggledCDIAtRealSink(t *testing.T) {
	sanitized := sanitizeLikeRestore(t,
		map[string]string{
			"cdi.k8s.io/gpu":               "evil.com/gpu=all", // smuggled
			"io.kubernetes.container.hash": "h",                // legit bookkeeping
		},
		nil, // the live create request asked for no device
	)

	keys, devices, err := cdi.ParseAnnotations(sanitized)
	if err != nil {
		t.Fatalf("cdi.ParseAnnotations: %v", err)
	}
	if len(devices) != 0 || len(keys) != 0 {
		t.Fatalf("smuggled checkpoint CDI survived to the CDI sink: keys=%v devices=%v", keys, devices)
	}
	if sanitized["io.kubernetes.container.hash"] != "h" {
		t.Errorf("legit kubelet bookkeeping annotation was dropped: %v", sanitized)
	}
}

// A device the live (trusted) create request asked for must still reach the CDI
// sink -- sanitization keeps create-request annotations as-is.
func TestRestoreSanitizeKeepsLiveRequestCDIAtRealSink(t *testing.T) {
	sanitized := sanitizeLikeRestore(t,
		map[string]string{"cdi.k8s.io/gpu": "evil.com/gpu=all"},    // checkpoint smuggle
		map[string]string{"cdi.k8s.io/net": "vendor.com/net=eth0"}, // live request, legit
	)

	_, devices, err := cdi.ParseAnnotations(sanitized)
	if err != nil {
		t.Fatalf("cdi.ParseAnnotations: %v", err)
	}
	if len(devices) != 1 || devices[0] != "vendor.com/net=eth0" {
		t.Fatalf("expected exactly the live-request device to survive, got %v", devices)
	}
}

// NOTE: full end-to-end CRImportCheckpoint coverage (blockIO/RDT class survival,
// operator passthrough, the kubelet re-supply question) requires a kubelet +
// containerd node and is tracked as the integration checklist in
// docs/rfc/restore-api.md. These two tests pin the security-critical CDI path at
// the real sink, which is what the unit suite in ./restore cannot reach.
