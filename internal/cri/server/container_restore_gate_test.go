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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/sandbox"
	sandboxstore "github.com/containerd/containerd/v2/internal/cri/store/sandbox"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// gateSandboxService lets CreateContainer get far enough to hit the restore
// gate; everything else falls back to the not-implemented fake.
type gateSandboxService struct {
	fakeSandboxService
}

func (g *gateSandboxService) SandboxStatus(_ context.Context, _ string, sandboxID string, _ bool) (sandbox.ControllerStatus, error) {
	return sandbox.ControllerStatus{SandboxID: sandboxID, Pid: 1234}, nil
}

func newRestoreGateTestService(t *testing.T) (*criService, *runtime.CreateContainerRequest) {
	t.Helper()
	c := newTestCRIService()
	c.sandboxService = &gateSandboxService{}

	sb := sandboxstore.NewSandbox(
		sandboxstore.Metadata{
			ID:     "gate-sandbox-id",
			Name:   "gate-sandbox-name",
			Config: &runtime.PodSandboxConfig{Metadata: &runtime.PodSandboxMetadata{Name: "p", Namespace: "ns", Uid: "uid"}},
		},
		sandboxstore.Status{State: sandboxstore.StateReady},
	)
	if err := c.sandboxStore.Add(sb); err != nil {
		t.Fatalf("failed to add test sandbox: %v", err)
	}

	// A real file on disk: CreateContainer treats an image that stats as a file
	// as a checkpoint archive, which is exactly the implicit tenant-reachable
	// path the gate must close.
	archivePath := filepath.Join(t.TempDir(), "checkpoint.tar")
	if err := os.WriteFile(archivePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	req := &runtime.CreateContainerRequest{
		PodSandboxId: "gate-sandbox-id",
		Config: &runtime.ContainerConfig{
			Metadata: &runtime.ContainerMetadata{Name: "restored-ctr"},
			Image:    &runtime.ImageSpec{Image: archivePath},
		},
		SandboxConfig: &runtime.PodSandboxConfig{
			Metadata: &runtime.PodSandboxMetadata{Name: "p", Namespace: "ns", Uid: "uid"},
		},
	}
	return c, req
}

func TestCreateContainerCheckpointRestoreDisabledByDefault(t *testing.T) {
	c, req := newRestoreGateTestService(t)
	if c.config.EnableCheckpointRestore {
		t.Fatal("test config must have checkpoint restore disabled by default")
	}

	_, err := c.CreateContainer(context.Background(), req)
	if err == nil {
		t.Fatal("CreateContainer accepted a checkpoint image with restore disabled (fail-open)")
	}
	if !strings.Contains(err.Error(), "checkpoint restore is disabled") {
		t.Fatalf("expected the restore gate error, got: %v", err)
	}
}

func TestCreateContainerCheckpointRestoreOptIn(t *testing.T) {
	c, req := newRestoreGateTestService(t)
	c.config.EnableCheckpointRestore = true

	_, err := c.CreateContainer(context.Background(), req)
	// The fake environment cannot complete a CRIU restore; the point is that
	// the gate opened and the request reached the restore path instead of being
	// rejected by the gate.
	if err != nil && strings.Contains(err.Error(), "checkpoint restore is disabled") {
		t.Fatalf("gate rejected the restore despite enable_checkpoint_restore=true: %v", err)
	}
	if err == nil {
		t.Fatal("expected the fake-environment restore to fail past the gate")
	}
}
