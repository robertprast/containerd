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
	"fmt"

	"github.com/distribution/reference"
)

// NewMetadataValidator returns the built-in [Validator] that every restore runs:
// it checks that the checkpoint's untrusted metadata is structurally sound
// BEFORE the restore commits any persistent host-side effect. In particular the
// base-image references from config.dump are validated here, before they are
// used to pull an image or write a tag into the shared image store.
//
// This validator is about structural integrity, not provenance. Signature /
// attestation verification is a separate [Validator] an operator can register
// on top.
func NewMetadataValidator() Validator {
	return metadataValidator{}
}

type metadataValidator struct{}

func (metadataValidator) Name() string { return "checkpoint-metadata" }

func (metadataValidator) Validate(_ context.Context, c *Checkpoint) error {
	if c.Config == nil {
		return errors.New("checkpoint has no config.dump metadata")
	}
	if c.Status == nil {
		return errors.New("checkpoint has no status.dump metadata")
	}
	if c.Spec == nil {
		return errors.New("checkpoint has no spec.dump metadata")
	}
	// The base-image references are checkpoint-authored and are later used for
	// an image pull and a tag write (persistent, shared host state). Reject
	// malformed references here, fail closed.
	if _, err := reference.ParseAnyReference(c.Config.RootfsImageRef); err != nil {
		return fmt.Errorf("checkpoint base image ref %q is not a valid reference: %w", c.Config.RootfsImageRef, err)
	}
	if _, err := reference.ParseAnyReference(c.Config.RootfsImageName); err != nil {
		return fmt.Errorf("checkpoint base image name %q is not a valid repository/tag: %w", c.Config.RootfsImageName, err)
	}
	return nil
}
