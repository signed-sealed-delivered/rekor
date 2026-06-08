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

// Package rhmtcutil provides Merkle tree computation utilities for RH MTC entry types.
package rhmtcutil

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/sigstore/rekor/pkg/types/rhmtc"
)

// ComputeLeafHash returns the RFC 6962 leaf hash for a TBS entry:
// SHA-256(0x00 || serialize(entry)).
func ComputeLeafHash(e rhmtc.TBSEntry) ([32]byte, error) {
	if len(e.PubKeyHash) != 32 {
		return [32]byte{}, errors.New("pubKeyHash must be 32 bytes")
	}
	serialized, err := serialize(e)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(serialized)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

// ComputeMerkleRoot builds a Merkle tree from entries and returns the root hash.
func ComputeMerkleRoot(entries []rhmtc.TBSEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, errors.New("cannot compute root for empty entries list")
	}
	leaves := make([][]byte, 0, len(entries))
	for i, e := range entries {
		leaf, err := ComputeLeafHash(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		leaves = append(leaves, leaf[:])
	}
	current := leaves
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, hashInterior(current[i], current[i+1]))
			} else {
				next = append(next, current[i])
			}
		}
		current = next
	}
	return current[0], nil
}

// ParseBatchEntries deserializes the batch blob produced by Fulcio's
// serializeBatchEntries: uint32(count) || (uint32(len) || TBSEntry)*.
func ParseBatchEntries(data []byte) ([]rhmtc.TBSEntry, error) {
	if len(data) < 4 {
		return nil, errors.New("batch data too short")
	}
	count := binary.BigEndian.Uint32(data[0:4])
	pos := 4
	entries := make([]rhmtc.TBSEntry, 0, count)
	for i := range count {
		if pos+4 > len(data) {
			return nil, fmt.Errorf("entry %d: unexpected end of data reading length", i)
		}
		entryLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if pos+entryLen > len(data) {
			return nil, fmt.Errorf("entry %d: unexpected end of data reading body", i)
		}
		entry, err := deserializeTBSEntry(data[pos : pos+entryLen])
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		entries = append(entries, entry)
		pos += entryLen
	}
	return entries, nil
}

func deserializeTBSEntry(b []byte) (rhmtc.TBSEntry, error) {
	var e rhmtc.TBSEntry
	pos := 0

	issuer, n, err := readLen16(b, pos)
	if err != nil {
		return e, fmt.Errorf("issuer: %w", err)
	}
	e.Issuer = issuer
	pos += n

	if pos+8 > len(b) {
		return e, errors.New("not_before: unexpected end")
	}
	e.NotBefore = int64(binary.BigEndian.Uint64(b[pos : pos+8]))
	pos += 8

	if pos+8 > len(b) {
		return e, errors.New("not_after: unexpected end")
	}
	e.NotAfter = int64(binary.BigEndian.Uint64(b[pos : pos+8]))
	pos += 8

	subject, n, err := readLen16(b, pos)
	if err != nil {
		return e, fmt.Errorf("subject: %w", err)
	}
	e.Subject = string(subject)
	pos += n

	spka, n, err := readLen16(b, pos)
	if err != nil {
		return e, fmt.Errorf("subject_public_key_algorithm: %w", err)
	}
	e.SubjectPublicKeyAlgorithm = spka
	pos += n

	if pos+32 > len(b) {
		return e, errors.New("pub_key_hash: unexpected end")
	}
	e.PubKeyHash = make([]byte, 32)
	copy(e.PubKeyHash, b[pos:pos+32])
	pos += 32

	if pos+2 > len(b) {
		return e, errors.New("extensions count: unexpected end")
	}
	extCount := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2

	e.Extensions = make([]rhmtc.Extension, 0, extCount)
	for i := range extCount {
		oid, n, err := readLen16(b, pos)
		if err != nil {
			return e, fmt.Errorf("extension %d oid: %w", i, err)
		}
		pos += n
		val, n, err := readLen16(b, pos)
		if err != nil {
			return e, fmt.Errorf("extension %d value: %w", i, err)
		}
		pos += n
		e.Extensions = append(e.Extensions, rhmtc.Extension{OID: oid, Value: val})
	}

	return e, nil
}

func readLen16(b []byte, pos int) ([]byte, int, error) {
	if pos+2 > len(b) {
		return nil, 0, errors.New("unexpected end reading length")
	}
	l := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	if pos+2+l > len(b) {
		return nil, 0, errors.New("unexpected end reading data")
	}
	out := make([]byte, l)
	copy(out, b[pos+2:pos+2+l])
	return out, 2 + l, nil
}

func serialize(e rhmtc.TBSEntry) ([]byte, error) {
	size := 2 + len(e.Issuer) + 8 + 8 + 2 + len(e.Subject) + 2 + len(e.SubjectPublicKeyAlgorithm) + 32 + 2
	for _, ext := range e.Extensions {
		size += 2 + len(ext.OID) + 2 + len(ext.Value)
	}
	buf := make([]byte, 0, size)
	buf = appendLen16(buf, e.Issuer)
	buf = binary.BigEndian.AppendUint64(buf, uint64(e.NotBefore))
	buf = binary.BigEndian.AppendUint64(buf, uint64(e.NotAfter))
	buf = appendLen16(buf, []byte(e.Subject))
	buf = appendLen16(buf, e.SubjectPublicKeyAlgorithm)
	buf = append(buf, e.PubKeyHash...)
	if len(e.Extensions) > 0xFFFF {
		return nil, fmt.Errorf("too many extensions: %d", len(e.Extensions))
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(e.Extensions)))
	for _, ext := range e.Extensions {
		buf = appendLen16(buf, ext.OID)
		buf = appendLen16(buf, ext.Value)
	}
	return buf, nil
}

func hashInterior(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func appendLen16(buf, data []byte) []byte {
	if len(data) > 0xFFFF {
		panic(fmt.Sprintf("data too long for uint16 length prefix: %d bytes", len(data)))
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(data)))
	return append(buf, data...)
}
