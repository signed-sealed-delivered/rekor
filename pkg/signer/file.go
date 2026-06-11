/*
Copyright The Rekor Authors.

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

package signer

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// returns an file based signer and verify, used for spinning up local instances
type File struct {
	signature.SignerVerifier
}

func NewFile(keyPath, keyPass string) (*File, error) {
	fileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("file: provide a valid signer, %s is not valid: %w", keyPath, err)
	}
	var pf cryptoutils.PassFunc
	if keyPass != "" {
		pf = func(_ bool) ([]byte, error) { return []byte(keyPass), nil }
	}
	opaqueKey, err := cryptoutils.UnmarshalPEMToPrivateKey(fileBytes, pf)
	if err != nil {
		return nil, fmt.Errorf("file: provide a valid signer, %s is not valid: %w", keyPath, err)
	}
	sv, err := signature.LoadDefaultSignerVerifier(opaqueKey)
	if err != nil {
		return nil, fmt.Errorf("file: loaded private key from %s can't be used to sign: %w", keyPath, err)
	}
	return &File{sv}, nil
}
