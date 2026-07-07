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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

const defaultMTCFlushInterval = 500 * time.Millisecond

// SignerConfig configures a single signer entry.
// Set MTCCosigner to true if this key is an MTC batch cosigner.
type SignerConfig struct {
	SigningSchemeOrKeyPath string `json:"signingSchemeOrKeyPath" yaml:"signingSchemeOrKeyPath"`
	FileSignerPassword     string `json:"fileSignerPassword" yaml:"fileSignerPassword"`
	TinkKEKURI             string `json:"tinkKEKURI" yaml:"tinkKEKURI"`
	TinkKeysetPath         string `json:"tinkKeysetPath" yaml:"tinkKeysetPath"`
	GCPKMSRetries          uint   `json:"gcpkmsRetries" yaml:"gcpkmsRetries"`
	GCPKMSTimeout          uint   `json:"gcpkmsTimeout" yaml:"gcpkmsTimeout"`
	MTCCosigner            bool   `json:"mtcCosigner,omitempty" yaml:"mtcCosigner,omitempty"`
}

// Duration is a time.Duration that round-trips through JSON/YAML as a
// human-readable string (e.g. "500ms"). sigs.k8s.io/yaml converts YAML to JSON
// before unmarshaling, so the built-in time.Duration (int64) cannot parse
// string values that appear in config files.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(dur)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string or integer: %w", err)
	}
	*d = Duration(n)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// MTCConfig holds shared MTC batch-signer settings. All MTC cosigner entries in
// a SigningConfig share these values.
type MTCConfig struct {
	LogID         string   `json:"logID,omitempty" yaml:"logID,omitempty"`
	LogOrigin     string   `json:"logOrigin,omitempty" yaml:"logOrigin,omitempty"`
	LogNumber     uint16   `json:"logNumber,omitempty" yaml:"logNumber,omitempty"`
	BatchSize     int      `json:"batchSize,omitempty" yaml:"batchSize,omitempty"`
	FlushInterval Duration `json:"flushInterval,omitempty" yaml:"flushInterval,omitempty"`
}

// SigningConfig initializes signers for a specific shard.
// For multi-signer mode, populate Signers with multiple entries; otherwise use the embedded SignerConfig fields.
type SigningConfig struct {
	SignerConfig
	MTC *MTCConfig `json:"mtc,omitempty" yaml:"mtc,omitempty"`

	// Multiple signers; when more than one is configured, all entries are signed by each signer.
	Signers []SignerConfig `json:"signers,omitempty" yaml:"signers,omitempty"`
}

func (sc SigningConfig) IsUnset() bool {
	if len(sc.Signers) > 0 {
		return false
	}
	if sc.MTC != nil {
		return false
	}
	return sc.SignerConfig == (SignerConfig{})
}

// GetSignerConfigs returns the list of individual signer configs.
// If Signers is populated, those take precedence; otherwise the embedded SignerConfig is wrapped.
func (sc SigningConfig) GetSignerConfigs() []SignerConfig {
	if len(sc.Signers) > 0 {
		return sc.Signers
	}
	return []SignerConfig{sc.SignerConfig}
}

// NewFromConfig creates a signer from a single SignerConfig.
// Entries with MTCCosigner: true must go through NewMultipleFromConfig.
func NewFromConfig(ctx context.Context, cfg SignerConfig) (signature.Signer, error) {
	if cfg.MTCCosigner {
		return nil, errors.New("MTC cosigner entry requires SigningConfig.MTC; use NewMultipleFromConfig")
	}
	return New(ctx, cfg.SigningSchemeOrKeyPath, cfg.FileSignerPassword,
		cfg.TinkKEKURI, cfg.TinkKeysetPath, cfg.GCPKMSRetries, cfg.GCPKMSTimeout)
}

// NewMultipleFromConfig creates one signer per entry in cfg. Each entry with
// MTCCosigner: false produces a signer via NewFromConfig. All entries with
// MTCCosigner: true are merged into a single MTCSigner using cfg.MTC for shared
// settings, inserted at the position of the first MTC entry so ordering controls
// whether it is primary or additional.
func NewMultipleFromConfig(ctx context.Context, cfg SigningConfig) ([]signature.Signer, error) {
	configs := cfg.GetSignerConfigs()
	if len(configs) == 0 {
		return nil, errors.New("no signer configurations provided")
	}

	var signers []signature.Signer
	var mtcCosigners []signature.CosignerConfig
	mtcInsertPos := -1

	for i, sc := range configs {
		if sc.MTCCosigner {
			if cfg.MTC == nil {
				return nil, fmt.Errorf("signer %d has mtcCosigner: true but no mtc config block is set", i)
			}
			pf := cryptoutils.SkipPassword
			if sc.FileSignerPassword != "" {
				pf = cryptoutils.StaticPasswordFunc([]byte(sc.FileSignerPassword))
			}
			key, err := signature.LoadSignerFromPEMFileWithOpts(sc.SigningSchemeOrKeyPath, pf)
			if err != nil {
				return nil, fmt.Errorf("loading MTC cosigner key %d: %w", i, err)
			}
			mtcCosigners = append(mtcCosigners, signature.CosignerConfig{Key: key})
			if len(mtcCosigners) == 1 {
				mtcInsertPos = len(signers)
			}
		} else {
			s, err := NewFromConfig(ctx, sc)
			if err != nil {
				return nil, fmt.Errorf("creating signer %d: %w", i, err)
			}
			signers = append(signers, s)
		}
	}

	if len(mtcCosigners) > 0 {
		flushInterval := time.Duration(cfg.MTC.FlushInterval)
		if flushInterval <= 0 {
			flushInterval = defaultMTCFlushInterval
		}
		bs, err := signature.NewMTCSigner(signature.MTCSignerConfig{
			LogID:         cfg.MTC.LogID,
			LogOrigin:     cfg.MTC.LogOrigin,
			LogNumber:     cfg.MTC.LogNumber,
			Cosigners:     mtcCosigners,
			BatchSize:     cfg.MTC.BatchSize,
			FlushInterval: flushInterval,
		})
		if err != nil {
			return nil, fmt.Errorf("creating MTC batch signer: %w", err)
		}
		bs.Start(ctx)
		signers = slices.Insert(signers, mtcInsertPos, signature.Signer(bs))
	}

	return signers, nil
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
