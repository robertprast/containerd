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
	"strings"
	"testing"

	crmetadata "github.com/checkpoint-restore/checkpointctl/lib"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func validCheckpoint() *Checkpoint {
	return &Checkpoint{
		ImageRef: "example.com/checkpoints/app:v1",
		Config: &crmetadata.ContainerConfig{
			RootfsImageRef:  "docker.io/library/nginx@sha256:0123456789012345678901234567890123456789012345678901234567890123",
			RootfsImageName: "docker.io/library/nginx:latest",
		},
		Spec:   &runtimespec.Spec{},
		Status: &runtime.ContainerStatus{},
	}
}

func TestMetadataValidator(t *testing.T) {
	v := NewMetadataValidator()
	ctx := context.Background()

	if err := v.Validate(ctx, validCheckpoint()); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}

	for name, tc := range map[string]struct {
		mutate  func(c *Checkpoint)
		errLike string
	}{
		"missing config.dump": {
			mutate:  func(c *Checkpoint) { c.Config = nil },
			errLike: "config.dump",
		},
		"missing status.dump": {
			mutate:  func(c *Checkpoint) { c.Status = nil },
			errLike: "status.dump",
		},
		"missing spec.dump": {
			mutate:  func(c *Checkpoint) { c.Spec = nil },
			errLike: "spec.dump",
		},
		"empty base image ref": {
			mutate:  func(c *Checkpoint) { c.Config.RootfsImageRef = "" },
			errLike: "not a valid reference",
		},
		"malformed base image ref": {
			mutate:  func(c *Checkpoint) { c.Config.RootfsImageRef = "in valid ref" },
			errLike: "not a valid reference",
		},
		"empty base image name": {
			mutate:  func(c *Checkpoint) { c.Config.RootfsImageName = "" },
			errLike: "not a valid repository/tag",
		},
		"malformed base image name": {
			mutate:  func(c *Checkpoint) { c.Config.RootfsImageName = "UPPER CASE bad" },
			errLike: "not a valid repository/tag",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := validCheckpoint()
			tc.mutate(c)
			err := v.Validate(ctx, c)
			if err == nil {
				t.Fatal("expected validation error, got nil (fail-open)")
			}
			if !strings.Contains(err.Error(), tc.errLike) {
				t.Fatalf("error %q does not mention %q", err, tc.errLike)
			}
		})
	}
}

// The production wiring in CRImportCheckpoint: RequireVerified policy plus the
// built-in metadata validator. A structurally broken checkpoint must abort
// Prepare before any annotation reaches the container config.
func TestPrepareWithMetadataValidator(t *testing.T) {
	r := New(
		Policy{Annotations: DefaultAnnotationPolicy(), RequireVerified: true},
		WithValidator(NewMetadataValidator()),
	)
	ctx := context.Background()

	good := validCheckpoint()
	good.Annotations = map[string]string{
		"io.kubernetes.container.hash": "h",
		"cdi.k8s.io/gpu":               "evil.com/gpu=all",
	}
	res, err := r.Prepare(ctx, good, nil)
	if err != nil {
		t.Fatalf("Prepare on valid checkpoint: %v", err)
	}
	if res.Annotations["io.kubernetes.container.hash"] != "h" {
		t.Errorf("bookkeeping annotation lost: %v", res.Annotations)
	}
	if _, ok := res.Annotations["cdi.k8s.io/gpu"]; ok {
		t.Errorf("smuggled CDI annotation survived: %v", res.Annotations)
	}

	bad := validCheckpoint()
	bad.Config = nil
	if _, err := r.Prepare(ctx, bad, nil); err == nil {
		t.Fatal("Prepare accepted a checkpoint with no config.dump")
	}
}
