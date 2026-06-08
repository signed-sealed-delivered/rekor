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

// Package rhmtcmonitoring implements the rhmtcmonitoring entry type for Rekor.
//
// An rhmtcmonitoring entry stores the serialized batch of TBSCertificateLogEntry
// records produced by Fulcio in a defined binary format (uint32 count ||
// (uint32 len || entry)*) that monitors parse to extract identity data. Canonicalize returns the raw bytes
// directly so the Trillian leaf value is the batch bytes themselves, giving:
//
//	leaf_hash = SHA-256(0x00 || data)
//
// This matches the rekor-tiles formula exactly, making the leaf hash and the
// ComputeMerkleRoot(ParseBatchEntries(data)) result backend-agnostic.
//
// Monitor cross-entry verification: after retrieving both the rhmtcmonitoring
// entry (this entry) and the corresponding rhmtccommitment entry, monitors MUST
// verify that ComputeMerkleRoot(ParseBatchEntries(data)) equals
// subtreeSignatures[i].subtreeRoot in the commitment entry. This confirms the
// commitment's signatures cover the exact batch data that was logged.
package rhmtcmonitoring

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/internal/log"
	pkitypes "github.com/sigstore/rekor/pkg/pki/pkitypes"
	"github.com/sigstore/rekor/pkg/types"
	rhmtcmonitoringtype "github.com/sigstore/rekor/pkg/types/rhmtcmonitoring"
	"github.com/sigstore/rekor/pkg/util/rhmtcutil"
)

const APIVERSION = "0.0.1"

func init() {
	if err := rhmtcmonitoringtype.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	obj models.RhmtcmonitoringV001Schema
}

func (v V001Entry) APIVersion() string { return APIVERSION }

func NewEntry() types.EntryImpl { return &V001Entry{} }

// DecodeEntry populates output from the raw spec value.
func DecodeEntry(input any, output *models.RhmtcmonitoringV001Schema) error {
	if output == nil {
		return fmt.Errorf("nil output *models.RhmtcmonitoringV001Schema")
	}
	var m models.RhmtcmonitoringV001Schema
	switch data := input.(type) {
	case map[string]any:
		if d, ok := data["data"].(string); ok && d != "" {
			decoded := make([]byte, base64.StdEncoding.DecodedLen(len(d)))
			n, err := base64.StdEncoding.Decode(decoded, []byte(d))
			if err != nil {
				return fmt.Errorf("failed parsing base64 data: %w", err)
			}
			b := strfmt.Base64(decoded[:n])
			m.Data = &b
		}
		*output = m
		return nil
	case *models.RhmtcmonitoringV001Schema:
		if data == nil {
			return fmt.Errorf("nil *models.RhmtcmonitoringV001Schema")
		}
		*output = *data
		return nil
	case models.RhmtcmonitoringV001Schema:
		*output = data
		return nil
	default:
		return fmt.Errorf("unsupported input type %T for DecodeEntry", input)
	}
}

// IndexKeys parses the batch binary format to extract subjects and pubKeyHashes
// for identity-based monitoring queries.
func (v V001Entry) IndexKeys() ([]string, error) {
	if v.obj.Data == nil || len(*v.obj.Data) == 0 {
		return nil, nil
	}
	entries, err := rhmtcutil.ParseBatchEntries([]byte(*v.obj.Data))
	if err != nil {
		return nil, fmt.Errorf("parsing batch entries for index: %w", err)
	}
	var keys []string
	for _, e := range entries {
		if e.Subject != "" {
			keys = append(keys, e.Subject)
		}
		if len(e.PubKeyHash) == 32 {
			keys = append(keys, "sha256:"+hex.EncodeToString(e.PubKeyHash))
		}
	}
	return keys, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	m, ok := pe.(*models.Rhmtcmonitoring)
	if !ok {
		return errors.New("cannot unmarshal non rhmtcmonitoring v0.0.1 type")
	}
	if err := DecodeEntry(m.Spec, &v.obj); err != nil {
		return err
	}
	if err := v.obj.Validate(strfmt.Default); err != nil {
		return err
	}
	if v.obj.Data == nil || len(*v.obj.Data) == 0 {
		return errors.New("rhmtcmonitoring data must not be empty")
	}
	return nil
}

// Canonicalize returns the raw batch bytes directly. This makes the Trillian
// leaf value the raw bytes, so leaf_hash = SHA-256(0x00 || data), consistent
// with the rekor-tiles formula.
func (v *V001Entry) Canonicalize(_ context.Context) ([]byte, error) {
	if v.obj.Data == nil || len(*v.obj.Data) == 0 {
		return nil, &types.InputValidationError{Err: errors.New("rhmtcmonitoring data is empty")}
	}
	return []byte(*v.obj.Data), nil
}

func (v *V001Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	if len(props.ArtifactBytes) == 0 {
		return nil, errors.New("rhmtcmonitoring requires ArtifactBytes")
	}
	d := strfmt.Base64(props.ArtifactBytes)
	schema := models.RhmtcmonitoringV001Schema{Data: &d}
	entry := &models.Rhmtcmonitoring{}
	entry.APIVersion = conv.Pointer(APIVERSION)
	entry.Spec = &schema
	return entry, nil
}

func (v V001Entry) Verifiers() ([]pkitypes.PublicKey, error) { return nil, nil }

func (v V001Entry) ArtifactHash() (string, error) {
	if v.obj.Data == nil || len(*v.obj.Data) == 0 {
		return "", errors.New("rhmtcmonitoring v0.0.1 entry not initialized")
	}
	h := sha256.Sum256(*v.obj.Data)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.obj.Data == nil || len(*v.obj.Data) == 0 {
		return false, errors.New("missing data")
	}
	return true, nil
}

// NewMonitoringEntry creates a models.Rhmtcmonitoring from raw bytes.
// Used by the /rh/v1/log/monitoring handler.
func NewMonitoringEntry(rawBytes []byte) (*models.Rhmtcmonitoring, error) {
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("rawBytes must not be empty")
	}
	d := strfmt.Base64(rawBytes)
	schema := models.RhmtcmonitoringV001Schema{Data: &d}
	entry := &models.Rhmtcmonitoring{}
	entry.APIVersion = conv.Pointer(APIVERSION)
	entry.Spec = &schema
	return entry, nil
}
