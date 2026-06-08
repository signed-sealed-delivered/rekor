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

// Package rhmtccommitment implements the rhmtccommitment entry type for Rekor.
//
// An rhmtccommitment entry is the client-verifiable counterpart to the
// rhmtcmonitoring entry. Its body contains {logId, monitoringLogId,
// monitoringLogIndex, subtreeSignatures} as JSON. Because all of these
// fields are present in a certificate holder's bundle, the holder can
// independently reconstruct the canonical JSON, compute the leaf hash, and
// verify the inclusion proof without fetching the entry from the log.
package rhmtccommitment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/internal/log"
	pkitypes "github.com/sigstore/rekor/pkg/pki/pkitypes"
	"github.com/sigstore/rekor/pkg/types"
	rhmtccommitmenttype "github.com/sigstore/rekor/pkg/types/rhmtccommitment"
)

const APIVERSION = "0.0.1"

func init() {
	if err := rhmtccommitmenttype.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	obj models.RhmtccommitmentV001Schema
}

func (v V001Entry) APIVersion() string { return APIVERSION }

func NewEntry() types.EntryImpl { return &V001Entry{} }

// IndexKeys returns the commitment log ID as a searchable key.
func (v V001Entry) IndexKeys() ([]string, error) {
	if v.obj.LogID == nil {
		return nil, nil
	}
	return []string{"logid:" + hex.EncodeToString(*v.obj.LogID)}, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	c, ok := pe.(*models.Rhmtccommitment)
	if !ok {
		return errors.New("cannot unmarshal non rhmtccommitment v0.0.1 type")
	}
	if err := types.DecodeEntry(c.Spec, &v.obj); err != nil {
		return err
	}
	if err := v.obj.Validate(strfmt.Default); err != nil {
		return err
	}
	return v.validate()
}

func (v *V001Entry) validate() error {
	if v.obj.LogID == nil || len(*v.obj.LogID) != 32 {
		return &types.InputValidationError{Err: errors.New("logId must be 32 bytes")}
	}
	if v.obj.MonitoringLogID == nil || len(*v.obj.MonitoringLogID) != 32 {
		return &types.InputValidationError{Err: errors.New("monitoringLogId must be 32 bytes")}
	}
	if v.obj.MonitoringLogIndex == nil {
		return &types.InputValidationError{Err: errors.New("monitoringLogIndex is required")}
	}
	if len(v.obj.SubtreeSignatures) == 0 {
		return &types.InputValidationError{Err: errors.New("subtreeSignatures must not be empty")}
	}
	return nil
}

// Canonicalize marshals the commitment as canonical JSON. This is stored as
// the Trillian leaf value. Certificate holders reconstruct this same JSON from
// bundle fields to independently verify the leaf hash.
func (v *V001Entry) Canonicalize(_ context.Context) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, &types.InputValidationError{Err: err}
	}
	obj := models.Rhmtccommitment{}
	obj.APIVersion = conv.Pointer(APIVERSION)
	obj.Spec = v.obj
	canonical, err := json.Marshal(&obj)
	if err != nil {
		return nil, fmt.Errorf("marshaling canonical commitment entry: %w", err)
	}
	return canonical, nil
}

func (v *V001Entry) CreateFromArtifactProperties(_ context.Context, _ types.ArtifactProperties) (models.ProposedEntry, error) {
	return nil, errors.New("rhmtccommitment entries are created by Fulcio's batch processor")
}

func (v V001Entry) Verifiers() ([]pkitypes.PublicKey, error) { return nil, nil }

func (v V001Entry) ArtifactHash() (string, error) {
	if v.obj.LogID == nil {
		return "", errors.New("rhmtccommitment v0.0.1 entry not initialized")
	}
	return "logid:" + hex.EncodeToString(*v.obj.LogID), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if err := v.validate(); err != nil {
		return false, err
	}
	return true, nil
}

// NewCommitmentEntry creates a models.Rhmtccommitment from its component fields.
// Used by the /rh/v1/log/commitment handler.
func NewCommitmentEntry(logID, monitoringLogID []byte, monitoringLogIndex int64, subtreeSigs []*models.RhmtccommitmentV001SchemaSubtreeSignaturesItems0) (*models.Rhmtccommitment, error) {
	if len(logID) != 32 {
		return nil, fmt.Errorf("logID must be 32 bytes")
	}
	if len(monitoringLogID) != 32 {
		return nil, fmt.Errorf("monitoringLogID must be 32 bytes")
	}
	if len(subtreeSigs) == 0 {
		return nil, fmt.Errorf("subtreeSignatures must not be empty")
	}
	lid := strfmt.Base64(logID)
	mlid := strfmt.Base64(monitoringLogID)
	schema := models.RhmtccommitmentV001Schema{
		LogID:              &lid,
		MonitoringLogID:    &mlid,
		MonitoringLogIndex: &monitoringLogIndex,
		SubtreeSignatures:  subtreeSigs,
	}
	entry := &models.Rhmtccommitment{}
	entry.APIVersion = conv.Pointer(APIVERSION)
	entry.Spec = schema
	return entry, nil
}
