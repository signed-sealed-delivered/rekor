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

package rhmtc

// Extension is an OID+value pair carried in a TBS certificate log entry.
type Extension struct {
	OID   []byte
	Value []byte
}

// TBSEntry holds the fields needed to compute an MTC leaf hash.
// Field layout mirrors the IETF draft-ietf-plants-merkle-tree-certs
// TBSCertificateLogEntry structure and sigstore-go/pkg/rhmtc.SerializeTBSCertificateLogEntry.
type TBSEntry struct {
	Subject                   string
	PubKeyHash                []byte // Currently SHA-256 of SubjectPublicKeyInfo DER
	NotBefore                 int64
	NotAfter                  int64
	Issuer                    []byte
	SubjectPublicKeyAlgorithm []byte
	Extensions                []Extension
}
