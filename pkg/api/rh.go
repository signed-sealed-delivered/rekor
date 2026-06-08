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

package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	ttypes "github.com/google/trillian/types"
	"github.com/spf13/viper"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	rhmtccommitment_v001 "github.com/sigstore/rekor/pkg/types/rhmtccommitment/v0.0.1"
	rhmtcmonitoring_v001 "github.com/sigstore/rekor/pkg/types/rhmtcmonitoring/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
)

// rhSignerInfo is the JSON shape for GET /rh/v1/keys.
type rhSignerInfo struct {
	Name      string `json:"name"`
	PubKeyPEM string `json:"public_key_pem"`
	LogID     string `json:"log_id"` // hex-encoded log identifier
}

// GetRhKeys handles GET /rh/v1/keys, returning all checkpoint-signing public
// keys so that Fulcio's TLogClient can derive the log identity on startup.
func GetRhKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	activeRange := api.logRanges.GetActive()
	hostname := viper.GetString("rekor_server.hostname")

	keys := make([]rhSignerInfo, 0, len(activeRange.PemPubKeys))
	for i, pem := range activeRange.PemPubKeys {
		logID := ""
		if i < len(activeRange.LogIDs) {
			logID = activeRange.LogIDs[i]
		}
		name := hostname
		if i > 0 {
			name = fmt.Sprintf("%s/key%d", hostname, i+1)
		}
		keys = append(keys, rhSignerInfo{
			Name:      name,
			PubKeyPEM: pem,
			LogID:     logID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keys); err != nil {
		log.Logger.Errorf("encoding /rh/v1/keys response: %v", err)
	}
}

// rhAdditionalSET carries one additional SET with its associated log ID.
type rhAdditionalSET struct {
	LogID                string `json:"log_id"`
	SignedEntryTimestamp []byte `json:"signed_entry_timestamp"`
}

// rhEntryResponse is the JSON response for both /rh/v1/log/monitoring and
// /rh/v1/log/commitment.
type rhEntryResponse struct {
	LogIndex                        int64             `json:"log_index"`
	LeafHash                        string            `json:"leaf_hash"`
	InclusionHashes                 [][]byte          `json:"inclusion_hashes,omitempty"`
	RootHash                        string            `json:"root_hash,omitempty"`
	TreeSize                        int64             `json:"tree_size,omitempty"`
	Checkpoint                      string            `json:"checkpoint,omitempty"`
	IntegratedTime                  int64             `json:"integrated_time,omitempty"`
	SignedEntryTimestamp            []byte            `json:"signed_entry_timestamp,omitempty"`
	AdditionalSignedEntryTimestamps []rhAdditionalSET `json:"additional_signed_entry_timestamps,omitempty"`
}

// addEntry is the shared logic for adding a JCS-canonicalized entry to the log.
// It applies JSON canonicalization (RFC 8785) to the entry before adding it to
// Trillian. Use addBinaryEntry for entries whose leaf is raw binary (not JSON).
func addEntry(w http.ResponseWriter, r *http.Request, proposedEntry models.ProposedEntry, logEntryKind string) {
	ctx := r.Context()

	entryImpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		http.Error(w, "creating entry: "+err.Error(), http.StatusBadRequest)
		return
	}

	leaf, err := types.CanonicalizeEntry(ctx, entryImpl)
	if err != nil {
		log.ContextLogger(ctx).Errorf("canonicalizing %s entry: %v", logEntryKind, err)
		http.Error(w, "canonicalizing entry: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addEntryWithLeaf(w, r, leaf, logEntryKind)
}

// addBinaryEntry adds an entry whose leaf value is raw binary (not JSON). The
// leaf is obtained by calling entry.Canonicalize directly, bypassing the JCS
// step. Used for rhmtcmonitoring entries whose leaf hash is SHA-256(0x00 || data).
func addBinaryEntry(w http.ResponseWriter, r *http.Request, proposedEntry models.ProposedEntry, logEntryKind string) {
	ctx := r.Context()

	entryImpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		http.Error(w, "creating entry: "+err.Error(), http.StatusBadRequest)
		return
	}

	leaf, err := entryImpl.Canonicalize(ctx)
	if err != nil {
		log.ContextLogger(ctx).Errorf("canonicalizing %s entry: %v", logEntryKind, err)
		http.Error(w, "canonicalizing entry: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addEntryWithLeaf(w, r, leaf, logEntryKind)
}

// addEntryWithLeaf submits the pre-computed leaf bytes to Trillian, then
// collects and returns the rhEntryResponse (inclusion proof, checkpoint, SETs).
func addEntryWithLeaf(w http.ResponseWriter, r *http.Request, leaf []byte, logEntryKind string) {
	ctx := r.Context()

	tc, err := api.trillianClientManager.GetTrillianClient(api.ActiveTreeID())
	if err != nil {
		log.ContextLogger(ctx).Errorf("getting trillian client: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := tc.AddLeaf(ctx, leaf)
	if resp.Status != codes.OK {
		log.ContextLogger(ctx).Errorf("adding %s leaf: %v", logEntryKind, resp.Err)
		http.Error(w, "adding entry to log: "+resp.Err.Error(), http.StatusInternalServerError)
		return
	}

	insertionStatus := resp.GetAddResult.QueuedLeaf.Status
	if insertionStatus != nil && insertionStatus.Code != 0 {
		log.ContextLogger(ctx).Errorf("%s leaf insertion status: %v", logEntryKind, insertionStatus)
		http.Error(w, fmt.Sprintf("entry insertion error: %v", insertionStatus.String()), http.StatusInternalServerError)
		return
	}

	metricNewEntries.Inc()

	queuedLeaf := resp.GetAddResult.QueuedLeaf.Leaf
	leafHash := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(leaf))
	virtualIndex := sharding.VirtualLogIndex(queuedLeaf.LeafIndex, api.logRanges.GetActive().TreeID, api.logRanges)

	result := rhEntryResponse{
		LogIndex:       virtualIndex,
		LeafHash:       leafHash,
		IntegratedTime: queuedLeaf.IntegrateTimestamp.AsTime().Unix(),
	}

	if proofResult := resp.GetLeafAndProofResult; proofResult != nil && proofResult.SignedLogRoot != nil {
		root := &ttypes.LogRootV1{}
		if err := root.UnmarshalBinary(proofResult.SignedLogRoot.LogRoot); err != nil {
			log.ContextLogger(ctx).Warnf("unmarshalling log root: %v", err)
		} else {
			result.RootHash = hex.EncodeToString(root.RootHash)
			result.TreeSize = int64(root.TreeSize) //nolint:gosec
			if proofResult.Proof != nil {
				result.InclusionHashes = proofResult.Proof.Hashes
			}
			activeRange := api.logRanges.GetActive()
			scBytes, scErr := util.CreateAndSignCheckpointMultiple(ctx,
				viper.GetString("rekor_server.hostname"),
				api.ActiveTreeID(),
				root.TreeSize,
				root.RootHash,
				activeRange.Signers,
			)
			if scErr != nil {
				log.ContextLogger(ctx).Warnf("generating checkpoint: %v", scErr)
			} else {
				result.Checkpoint = string(scBytes)
			}
		}
	}

	logEntryAnon := models.LogEntryAnon{
		LogID:          conv.Pointer(api.logRanges.GetActive().LogID),
		LogIndex:       &virtualIndex,
		Body:           queuedLeaf.GetLeafValue(),
		IntegratedTime: conv.Pointer(queuedLeaf.IntegrateTimestamp.AsTime().Unix()),
	}
	activeRange := api.logRanges.GetActive()
	signatures, sigLogIDs, setErr := signEntryMultiple(ctx, activeRange.Signers, activeRange.LogIDs, logEntryAnon)
	if setErr != nil {
		log.ContextLogger(ctx).Warnf("generating SETs for %s entry: %v", logEntryKind, setErr)
	} else {
		result.SignedEntryTimestamp = signatures[0]
		for i, sig := range signatures[1:] {
			result.AdditionalSignedEntryTimestamps = append(
				result.AdditionalSignedEntryTimestamps,
				rhAdditionalSET{LogID: sigLogIDs[i+1], SignedEntryTimestamp: sig},
			)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.ContextLogger(ctx).Errorf("encoding %s response: %v", logEntryKind, err)
	}
}

// AddRhmtcMonitoringEntry handles POST /rh/v1/log/monitoring.
// Accepts raw batch bytes and stores them as an rhmtcmonitoring entry.
func AddRhmtcMonitoringEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 {
		http.Error(w, "request body must not be empty", http.StatusBadRequest)
		return
	}

	proposedEntry, err := rhmtcmonitoring_v001.NewMonitoringEntry(data)
	if err != nil {
		http.Error(w, "building proposed entry: "+err.Error(), http.StatusBadRequest)
		return
	}

	addBinaryEntry(w, r, proposedEntry, "rhmtcmonitoring")
}

// commitmentRequest is the JSON body for POST /rh/v1/log/commitment.
type commitmentRequest struct {
	LogID              []byte                                                        `json:"logId"`
	MonitoringLogID    []byte                                                        `json:"monitoringLogId"`
	MonitoringLogIndex int64                                                         `json:"monitoringLogIndex"`
	SubtreeSignatures  []*models.RhmtccommitmentV001SchemaSubtreeSignaturesItems0   `json:"subtreeSignatures"`
}

// AddRhmtcCommitmentEntry handles POST /rh/v1/log/commitment.
// Accepts a JSON commitment body and stores it as an rhmtccommitment entry.
func AddRhmtcCommitmentEntry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "request body must not be empty", http.StatusBadRequest)
		return
	}

	var req commitmentRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "parsing commitment request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate logId lengths before constructing the entry.
	if len(req.LogID) != 32 {
		http.Error(w, "logId must be 32 bytes", http.StatusBadRequest)
		return
	}
	if len(req.MonitoringLogID) != 32 {
		http.Error(w, "monitoringLogId must be 32 bytes", http.StatusBadRequest)
		return
	}

	lid := strfmt.Base64(req.LogID)
	mlid := strfmt.Base64(req.MonitoringLogID)
	schema := models.RhmtccommitmentV001Schema{
		LogID:              &lid,
		MonitoringLogID:    &mlid,
		MonitoringLogIndex: &req.MonitoringLogIndex,
		SubtreeSignatures:  req.SubtreeSignatures,
	}
	proposedEntry := &models.Rhmtccommitment{}
	proposedEntry.APIVersion = conv.Pointer(rhmtccommitment_v001.APIVERSION)
	proposedEntry.Spec = schema

	_ = ctx
	addEntry(w, r, proposedEntry, "rhmtccommitment")
}
