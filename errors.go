// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import "errors"

var (
	// ErrUnsupportedClient is returned for a remote client that cannot remain an auth.Client.
	ErrUnsupportedClient = errors.New("unsupported remote client")

	// ErrAmbiguousRepositoryCredentials is returned when one request needs different principals.
	ErrAmbiguousRepositoryCredentials = errors.New("ambiguous repository credentials")

	// ErrInvalidAuthConfig is returned when a configured credential source is invalid.
	ErrInvalidAuthConfig = errors.New("invalid auth configuration")

	// ErrConflictingEncodedAuthConfig is returned for conflicting encoded config aliases.
	ErrConflictingEncodedAuthConfig = errors.New("conflicting encoded auth configuration")

	// ErrNilRepository is returned when repository wrapping receives a nil repository.
	ErrNilRepository = errors.New("nil repository")

	// ErrNilRegistry is returned when registry wrapping receives a nil registry.
	ErrNilRegistry = errors.New("nil registry")

	// ErrInvalidInlineAuth is returned when an auth field lacks username/password syntax.
	ErrInvalidInlineAuth = errors.New("invalid inline auth")
)
