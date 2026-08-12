// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// configFile is the supported read-only subset of Docker-compatible config.
type configFile struct {
	// Auths maps server addresses or repository paths to inline credentials
	Auths map[string]authEntry `json:"auths"`
	// CredHelpers maps server addresses to credential helper suffixes
	CredHelpers map[string]string `json:"credHelpers"`
	// CredsStore is the default credential helper suffix
	CredsStore string `json:"credsStore"`
}

// authEntry is one Docker-compatible inline credential entry.
type authEntry struct {
	// Auth stores base64-encoded username and password separated by a colon
	Auth string `json:"auth"`
	// Username is an explicit username
	Username string `json:"username"`
	// Password is an explicit password
	Password string `json:"password"`
	// IdentityToken is an OAuth refresh or identity token
	IdentityToken string `json:"identitytoken"`
	// RegistryToken is a direct registry access token
	RegistryToken string `json:"registrytoken"`
}

// parsedAuth holds an already decoded immutable ORAS credential.
type parsedAuth struct {
	credential auth.Credential // credential is the decoded credential
}

// source is one immutable credential configuration source.
type source struct {
	hostStore  credentials.Store     // hostStore preserves ORAS host-level behavior for a file-backed source
	auths      map[string]parsedAuth // auths maps normalized config keys to decoded inline credentials
	helpers    map[string]string     // helpers maps host-only addresses to helper suffixes
	id         string                // id is a non-secret identifier for diagnostics and principal matching
	credsStore string                // credsStore is the source-wide host-only helper suffix
}

// resolvedCredential carries a credential and its non-secret security principal.
type resolvedCredential struct {
	principal  string          // principal identifies the source/key, without including secret material
	err        error           // err is a deferred resolution error
	credential auth.Credential // credential is the resolved ORAS credential
}

// loadSource parses an input source and constructs its host fallback store.
func loadSource(input inputSource) (source, error) {
	data := input.data

	if input.path != "" {
		var err error
		data, err = os.ReadFile(input.path)
		if err != nil {
			return source{}, fmt.Errorf("%w: read %s: %v", ErrInvalidAuthConfig, input.path, err)
		}
		input.id = "file:" + filepath.Clean(input.path)
	}

	var cfg configFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return source{}, fmt.Errorf("%w: %s", ErrInvalidAuthConfig, input.id)
	}

	// Decode inline credentials once. The resulting source is immutable,
	// so a caller recreates Adapter to pick up configuration changes
	s := source{
		id:         input.id,
		auths:      map[string]parsedAuth{},
		helpers:    cfg.CredHelpers,
		credsStore: cfg.CredsStore,
	}

	if input.path != "" {
		store, err := credentials.NewStore(input.path, credentials.StoreOptions{})
		if err != nil {
			return source{}, fmt.Errorf("%w: read %s", ErrInvalidAuthConfig, input.path)
		}
		s.hostStore = store
	}

	for key, entry := range cfg.Auths {
		cred, err := convertEntry(entry)
		if err != nil {
			return source{}, fmt.Errorf("%w: %s key %s", ErrInvalidAuthConfig, input.id, key)
		}
		s.auths[normalizeScopedKey(key)] = parsedAuth{credential: cred}
	}

	return s, nil
}

// convertEntry converts one config entry using ORAS-compatible field priority.
func convertEntry(entry authEntry) (auth.Credential, error) {
	// Token fields take precedence because ORAS must not combine credential forms
	if entry.RegistryToken != "" {
		return auth.Credential{AccessToken: entry.RegistryToken}, nil
	}
	if entry.IdentityToken != "" {
		return auth.Credential{RefreshToken: entry.IdentityToken}, nil
	}
	if entry.Username != "" || entry.Password != "" {
		return auth.Credential{Username: entry.Username, Password: entry.Password}, nil
	}

	if entry.Auth == "" {
		return auth.EmptyCredential, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
	if err != nil {
		return auth.EmptyCredential, err
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return auth.EmptyCredential, ErrInvalidInlineAuth
	}

	return auth.Credential{Username: username, Password: password}, nil
}

// hostCredential resolves a source's helper or inline host credential.
func (s source) hostCredential(ctx context.Context, host string) (auth.Credential, error) {
	if s.hostStore != nil {
		// Delegate file-backed lookup to ORAS to preserve Docker Hub normalization.
		return credentials.Credential(s.hostStore)(ctx, host)
	}

	address := credentials.ServerAddressFromHostname(host)

	// Match Docker's selection order per source.
	// Keeping sources separate is necessary because helper
	// precedence belongs to a configuration source.
	if helper := s.helpers[address]; helper != "" {
		// Helpers remain host-scoped; a repository key must never reach a helper
		return credentials.NewNativeStore(helper).Get(ctx, address)
	}
	if helper := s.helpers[host]; helper != "" {
		return credentials.NewNativeStore(helper).Get(ctx, host)
	}
	if s.credsStore != "" {
		return credentials.NewNativeStore(s.credsStore).Get(ctx, address)
	}

	// Path-scoped entries were resolved earlier; only exact host keys remain
	if entry, ok := s.auths[normalizeScopedKey(address)]; ok {
		return entry.credential, nil
	}
	if entry, ok := s.auths[normalizeScopedKey(host)]; ok {
		return entry.credential, nil
	}

	return auth.EmptyCredential, nil
}
