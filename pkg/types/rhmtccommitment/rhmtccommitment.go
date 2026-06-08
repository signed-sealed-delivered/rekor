// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rhmtccommitment

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
)

const KIND = "rhmtccommitment"

type BaseRhmtcCommitmentType struct {
	types.RekorType
}

func init() {
	types.TypeMap.Store(KIND, New)
}

func New() types.TypeImpl {
	t := BaseRhmtcCommitmentType{}
	t.Kind = KIND
	t.VersionMap = VersionMap
	return &t
}

var VersionMap = types.NewSemVerEntryFactoryMap()

func (rt BaseRhmtcCommitmentType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	if pe == nil {
		return nil, errors.New("proposed entry cannot be nil")
	}
	c, ok := pe.(*models.Rhmtccommitment)
	if !ok {
		return nil, fmt.Errorf("cannot unmarshal non rhmtccommitment type: %s", pe.Kind())
	}
	return rt.VersionedUnmarshal(c, *c.APIVersion)
}

func (rt *BaseRhmtcCommitmentType) CreateProposedEntry(ctx context.Context, version string, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if version == "" {
		version = rt.DefaultVersion()
	}
	ei, err := rt.VersionedUnmarshal(nil, version)
	if err != nil {
		return nil, fmt.Errorf("fetching rhmtccommitment version implementation: %w", err)
	}
	return ei.CreateFromArtifactProperties(ctx, props)
}

func (rt BaseRhmtcCommitmentType) DefaultVersion() string {
	return "0.0.1"
}
