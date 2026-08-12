// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"sort"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// resolve selects the scoped credential or a host fallback for one repository.
func (a *Adapter) resolve(
	ctx context.Context,
	host,
	repository string,
	fallback auth.CredentialFunc,
) resolvedCredential {
	for _, key := range candidates(host, repository) {
		// Candidate order is specificity; source order is the secondary tie-breaker
		for _, source := range a.sources {
			if entry, ok := source.auths[key]; ok && !emptyCredential(entry.credential) {
				return resolvedCredential{
					credential: entry.credential,
					principal:  "inline:" + source.id + "#" + key,
				}
			}
			// An empty exact entry is not a deny rule and must not shadow its parent
		}
	}

	return a.resolveHost(ctx, host, fallback)
}

// hostCredential returns only the credential component of host resolution.
func (a *Adapter) hostCredential(
	ctx context.Context,
	host string,
	fallback auth.CredentialFunc,
) (auth.Credential, error) {
	match := a.resolveHost(ctx, host, fallback)
	return match.credential, match.err
}

// resolveHost resolves source, caller, adapter, then anonymous host credentials.
func (a *Adapter) resolveHost(
	ctx context.Context,
	host string,
	fallback auth.CredentialFunc,
) resolvedCredential {
	for _, source := range a.sources {
		// Host fallback happens only after every scoped parent has been checked
		credential, err := source.hostCredential(ctx, host)
		if err != nil {
			return resolvedCredential{credential: auth.EmptyCredential, principal: "error:" + host, err: err}
		}
		if !emptyCredential(credential) {
			return resolvedCredential{credential: credential, principal: "host:" + source.id + "#" + host}
		}
	}

	for _, credentialFunc := range []auth.CredentialFunc{fallback, a.fallback} {
		if credentialFunc == nil {
			continue
		}

		credential, err := credentialFunc(ctx, host)
		if err != nil {
			return resolvedCredential{credential: auth.EmptyCredential, principal: "error:" + host, err: err}
		}
		if !emptyCredential(credential) {
			// Discovered host credentials precede caller fallback;
			// neither can override an earlier repository-scoped match.
			return resolvedCredential{credential: credential, principal: "fallback:" + host}
		}
	}

	return resolvedCredential{credential: auth.EmptyCredential, principal: "anonymous:" + host}
}

// candidates returns exact, segment-safe parent keys from most to least specific.
func candidates(host, repository string) []string {
	host = normalizeScopedKey(host)
	repository = strings.Trim(repository, "/")

	if host == "" ||
		strings.Contains(host, "/") ||
		repository == "" ||
		strings.Contains(repository, "//") {
		return nil // Invalid input must not be normalized into a broader authorization scope
	}

	keys := []string{}
	for repository != "" {
		keys = append(keys, host+"/"+repository)
		index := strings.LastIndexByte(repository, '/')
		if index < 0 {
			break
		}

		repository = repository[:index]
	}

	return keys
}

// repositoriesForHost extracts sorted repository resources from host scopes.
func repositoriesForHost(ctx context.Context, host string) []string {
	set := map[string]struct{}{}
	for _, scope := range auth.GetScopesForHost(ctx, host) {
		// Split at the outer delimiters only:
		// repository names need not be constrained by a naive colon-separated parser
		first, last := strings.IndexByte(scope, ':'), strings.LastIndexByte(scope, ':')
		if first <= 0 || last <= first || scope[:first] != "repository" {
			continue // Global and non-repository scopes are authorization hints, not identity
		}

		if repository := scope[first+1 : last]; repository != "" {
			set[repository] = struct{}{}
		}
	}

	repositories := make([]string, 0, len(set))
	for repository := range set {
		repositories = append(repositories, repository)
	}

	sort.Strings(repositories)
	return repositories
}

// normalizeScopedKey removes whitespace and a non-semantic trailing slash.
func normalizeScopedKey(key string) string {
	return strings.TrimSuffix(strings.TrimSpace(key), "/")
}

// emptyCredential reports whether a credential has no usable fields.
func emptyCredential(credential auth.Credential) bool {
	return credential == auth.EmptyCredential
}
