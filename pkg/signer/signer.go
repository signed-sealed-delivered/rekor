/*
Copyright 2021 The Sigstore Authors.

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
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"

	"google.golang.org/api/option"
	"google.golang.org/grpc"

	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"

	// these are imported to load the providers via init() calls
	_ "github.com/sigstore/sigstore/pkg/signature/kms/aws"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/azure"
	_ "github.com/sigstore/sigstore/pkg/signature/kms/hashivault"
)

// SignerConfig configures a single signer
type SignerConfig struct {
	SigningSchemeOrKeyPath string `json:"signingSchemeOrKeyPath" yaml:"signingSchemeOrKeyPath"`
	FileSignerPassword     string `json:"fileSignerPassword" yaml:"fileSignerPassword"`
	TinkKEKURI             string `json:"tinkKEKURI" yaml:"tinkKEKURI"`
	TinkKeysetPath         string `json:"tinkKeysetPath" yaml:"tinkKeysetPath"`
	GCPKMSRetries          uint   `json:"gcpkmsRetries" yaml:"gcpkmsRetries"`
	GCPKMSTimeout          uint   `json:"gcpkmsTimeout" yaml:"gcpkmsTimeout"`
}

func (sc SignerConfig) IsUnset() bool {
	return sc.SigningSchemeOrKeyPath == "" && sc.FileSignerPassword == "" &&
		sc.TinkKEKURI == "" && sc.TinkKeysetPath == ""
}

// SigningConfig initializes signers for a specific shard.
// For backwards compatibility, the single-signer fields are supported.
// For hybrid mode, use the Signers array.
type SigningConfig struct {
	// Single signer configuration (backwards compatible)
	SigningSchemeOrKeyPath string `json:"signingSchemeOrKeyPath" yaml:"signingSchemeOrKeyPath"`
	FileSignerPassword     string `json:"fileSignerPassword" yaml:"fileSignerPassword"`
	TinkKEKURI             string `json:"tinkKEKURI" yaml:"tinkKEKURI"`
	TinkKeysetPath         string `json:"tinkKeysetPath" yaml:"tinkKeysetPath"`
	GCPKMSRetries          uint   `json:"gcpkmsRetries" yaml:"gcpkmsRetries"`
	GCPKMSTimeout          uint   `json:"gcpkmsTimeout" yaml:"gcpkmsTimeout"`

	// Multiple signers for hybrid mode (takes precedence if non-empty)
	Signers []SignerConfig `json:"signers,omitempty" yaml:"signers,omitempty"`
}

func (sc SigningConfig) IsUnset() bool {
	if len(sc.Signers) > 0 {
		return false
	}
	return sc.SigningSchemeOrKeyPath == "" && sc.FileSignerPassword == "" &&
		sc.TinkKEKURI == "" && sc.TinkKeysetPath == ""
}

// GetSignerConfigs returns the list of signer configurations.
// If Signers array is set, returns those. Otherwise, returns a single-element
// slice with the legacy single-signer configuration.
func (sc SigningConfig) GetSignerConfigs() []SignerConfig {
	if len(sc.Signers) > 0 {
		return sc.Signers
	}
	// Backwards compatible: wrap single signer config
	return []SignerConfig{{
		SigningSchemeOrKeyPath: sc.SigningSchemeOrKeyPath,
		FileSignerPassword:     sc.FileSignerPassword,
		TinkKEKURI:             sc.TinkKEKURI,
		TinkKeysetPath:         sc.TinkKeysetPath,
		GCPKMSRetries:          sc.GCPKMSRetries,
		GCPKMSTimeout:          sc.GCPKMSTimeout,
	}}
}

func New(ctx context.Context, signer, pass, tinkKEKURI, tinkKeysetPath string, gcpkmsretries, gcpkmstimeout uint) (signature.Signer, error) {
	switch {
	case slices.ContainsFunc(kms.SupportedProviders(),
		func(s string) bool {
			return strings.HasPrefix(signer, s)
		}):
		opts := make([]signature.RPCOption, 0)
		if strings.HasPrefix(signer, gcp.ReferenceScheme) {
			callOpts := []grpc_retry.CallOption{grpc_retry.WithMax(gcpkmsretries), grpc_retry.WithPerRetryTimeout(time.Duration(gcpkmstimeout) * time.Second)}
			opts = append(opts, gcp.WithGoogleAPIClientOption(option.WithGRPCDialOption(grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor(callOpts...)))))
		}
		return kms.Get(ctx, signer, crypto.SHA256, opts...)
	case signer == MemoryScheme:
		return NewMemory()
	case signer == TinkScheme:
		return NewTinkSigner(ctx, tinkKEKURI, tinkKeysetPath)
	default:
		return NewFile(signer, pass)
	}
}

// NewFromConfig creates a signer from a SignerConfig
func NewFromConfig(ctx context.Context, cfg SignerConfig) (signature.Signer, error) {
	return New(ctx, cfg.SigningSchemeOrKeyPath, cfg.FileSignerPassword,
		cfg.TinkKEKURI, cfg.TinkKeysetPath, cfg.GCPKMSRetries, cfg.GCPKMSTimeout)
}

// NewMultipleFromConfig creates multiple signers from a SigningConfig.
// This is used for hybrid signing mode where multiple keys sign the same content.
func NewMultipleFromConfig(ctx context.Context, cfg SigningConfig) ([]signature.Signer, error) {
	configs := cfg.GetSignerConfigs()
	if len(configs) == 0 {
		return nil, errors.New("no signer configurations provided")
	}

	signers := make([]signature.Signer, 0, len(configs))
	for i, sc := range configs {
		s, err := NewFromConfig(ctx, sc)
		if err != nil {
			return nil, fmt.Errorf("creating signer %d: %w", i, err)
		}
		signers = append(signers, s)
	}
	return signers, nil
}
