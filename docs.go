// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

/*
Package orascope adds repository-path-aware credential selection to oras.land/oras-go/v2.

ORAS resolves credentials by registry host,
while Docker-compatible auth files can contain inline credentials for registry repository paths.
Adapter derives the active repository from ORAS request context scopes
and resolves inline auths by the most-specific path first, then by source priority.
A host-level credential is used only when no scoped inline credential matches.

Adapter preserves ORAS authentication transport behavior.
It wraps an existing *auth.Client rather than replacing remote.Client,
preserving Basic, Bearer, OAuth2, retry, redirect, and request-body retry behavior.
The wrapped cache is namespaced by exact repository scope
to prevent Basic and Bearer state leaking between sibling repositories.

Credential helpers and credsStore remain host-scoped.
Adapter never passes a repository path to a helper.
A request with multiple repository scopes must resolve to one non-secret principal identity
or fails with ErrAmbiguousRepositoryCredentials.
GuardMountFrom can filter incompatible cross-repository mount candidates.

NewDefault discovers

  - DOCKER_AUTH_CONFIG,
  - Docker and containers auth files,
  - legacy .dockercfg,
  - DOCKER_AUTH_CONFIG_BASE64 or DOCKER_AUTH_CONFIG_ENCODED.

Configuration is read into an immutable snapshot at construction time;
recreate Adapter after changing its configuration.

For use with an existing ORAS repository, call WrapRepository.
For repositories created by remote.Registry, call WrapRegistry. Both preserve *auth.Client.
*/
package orascope
