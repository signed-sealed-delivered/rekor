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

package tle

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	rekor_pb_common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	_ "github.com/sigstore/rekor/pkg/types/rhmtccommitment/v0.0.1"
	_ "github.com/sigstore/rekor/pkg/types/rhmtcmonitoring/v0.0.1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mtcLogEntryAnon(b64Body, logIDHex, checkpointEnvelope, rootHashHex string, hashes []string, logIndex, integratedTime int64) models.LogEntryAnon {
	return models.LogEntryAnon{
		Body:           b64Body,
		IntegratedTime: conv.Pointer(integratedTime),
		LogID:          conv.Pointer(logIDHex),
		LogIndex:       conv.Pointer(logIndex),
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				Checkpoint: conv.Pointer(checkpointEnvelope),
				Hashes:     hashes,
				LogIndex:   conv.Pointer(logIndex),
				RootHash:   conv.Pointer(rootHashHex),
				TreeSize:   conv.Pointer(int64(len(hashes) + 1)),
			},
			SignedEntryTimestamp: strfmt.Base64("set"),
		},
	}
}

func mtcWantTLE(logIndex, integratedTime int64, logIDHex, kind, version, checkpointEnvelope, rootHashHex string, hashes []string, body []byte) *rekor_pb.TransparencyLogEntry {
	logIDBytes, _ := hex.DecodeString(logIDHex)
	rootHashBytes, _ := hex.DecodeString(rootHashHex)
	hashSlices := make([][]byte, len(hashes))
	for i, h := range hashes {
		hashSlices[i], _ = hex.DecodeString(h)
	}
	return &rekor_pb.TransparencyLogEntry{
		LogIndex: logIndex,
		LogId:    &rekor_pb_common.LogId{KeyId: logIDBytes},
		KindVersion: &rekor_pb.KindVersion{
			Kind:    kind,
			Version: version,
		},
		IntegratedTime: integratedTime,
		InclusionPromise: &rekor_pb.InclusionPromise{
			SignedEntryTimestamp: []byte("set"),
		},
		InclusionProof: &rekor_pb.InclusionProof{
			Checkpoint: &rekor_pb.Checkpoint{Envelope: checkpointEnvelope},
			Hashes:     hashSlices,
			LogIndex:   logIndex,
			RootHash:   rootHashBytes,
			TreeSize:   int64(len(hashes) + 1),
		},
		CanonicalizedBody: body,
	}
}

// TestGenerateTransparencyLogEntry_RhmtcCommitment tests that the commitment
// entry (used by certificate holders for bundle verification) correctly
// generates a TLE. Commitment entries have JSON bodies, so they work with
// GenerateTransparencyLogEntry. Monitoring entries are used by monitors and
// do not go through GenerateTransparencyLogEntry.
func TestGenerateTransparencyLogEntry_RhmtcCommitment(t *testing.T) {
	logID := make([]byte, 32)
	monLogID := make([]byte, 32)
	monLogID[0] = 0x01
	monLogIndex := int64(42)
	alg := "ECDSA_P256_SHA_256"
	sig := strfmt.Base64([]byte("fake-sig"))
	subtreeRoot := strfmt.Base64(make([]byte, 32))
	treeSize := int64(10)
	start := int64(0)
	end := int64(10)

	lid := strfmt.Base64(logID)
	mlid := strfmt.Base64(monLogID)
	schema := models.RhmtccommitmentV001Schema{
		LogID:              &lid,
		MonitoringLogID:    &mlid,
		MonitoringLogIndex: &monLogIndex,
		SubtreeSignatures: []*models.RhmtccommitmentV001SchemaSubtreeSignaturesItems0{
			{
				Algorithm:   &alg,
				Signature:   &sig,
				SubtreeRoot: &subtreeRoot,
				TreeSize:    &treeSize,
				Start:       &start,
				End:         &end,
			},
		},
	}
	entry := models.Rhmtccommitment{}
	entry.APIVersion = conv.Pointer("0.0.1")
	entry.Spec = schema

	bodyBytes, err := json.Marshal(&entry)
	require.NoError(t, err)

	b64Body := base64.StdEncoding.EncodeToString(bodyBytes)
	logIDHex := hex.EncodeToString(logID)
	checkpoint := "rhmtccommitment-checkpoint"
	rootHashHex := "11223344"
	hashes := []string{logIDHex}

	anon := mtcLogEntryAnon(b64Body, logIDHex, checkpoint, rootHashHex, hashes, 1, 123)
	want := mtcWantTLE(1, 123, logIDHex, "rhmtccommitment", "0.0.1", checkpoint, rootHashHex, hashes, bodyBytes)

	got, err := GenerateTransparencyLogEntry(anon)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}
