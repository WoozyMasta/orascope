// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"strings"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// scopedCache applies a repository-scope namespace to an ORAS cache.
type scopedCache struct {
	adapter *Adapter   // adapter identifies the owner and prevents cross-adapter false idempotence.
	base    auth.Cache // base stores the namespaced cache records.
}

// noCache preserves auth.Client nil-cache behavior while allowing a cache marker.
type noCache struct{}

// Cache namespaces an ORAS cache by the exact repository scopes in context.
func (a *Adapter) Cache(base auth.Cache) auth.Cache {
	if cache, ok := base.(*scopedCache); ok && cache.adapter == a {
		return base
	}
	if base == nil {
		// auth.Client with Cache == nil must not begin caching solely because it was adapted.
		// noCache still marks the resulting client as wrapped.
		base = noCache{}
	}
	return &scopedCache{adapter: a, base: base}
}

// GetScheme always reports no cached scheme.
func (noCache) GetScheme(context.Context, string) (auth.Scheme, error) {
	return auth.SchemeUnknown, errdef.ErrNotFound
}

// GetToken always reports no cached token.
func (noCache) GetToken(context.Context, string, auth.Scheme, string) (string, error) {
	return "", errdef.ErrNotFound
}

// Set obtains a token without storing it.
func (noCache) Set(
	ctx context.Context,
	_ string,
	_ auth.Scheme,
	_ string,
	fetch func(context.Context) (string, error),
) (string, error) {
	return fetch(ctx)
}

// GetScheme obtains the scheme from the repository-specific namespace.
func (c *scopedCache) GetScheme(ctx context.Context, registry string) (auth.Scheme, error) {
	return c.base.GetScheme(ctx, cacheRegistry(ctx, registry))
}

// GetToken obtains the token from the repository-specific namespace.
func (c *scopedCache) GetToken(
	ctx context.Context,
	registry string,
	scheme auth.Scheme,
	key string,
) (string, error) {
	return c.base.GetToken(ctx, cacheRegistry(ctx, registry), scheme, key)
}

// Set fetches and stores the token in the repository-specific namespace.
func (c *scopedCache) Set(
	ctx context.Context,
	registry string,
	scheme auth.Scheme,
	key string,
	fetch func(context.Context) (string, error),
) (string, error) {
	return c.base.Set(ctx, cacheRegistry(ctx, registry), scheme, key, fetch)
}

// cacheRegistry derives a collision-free cache namespace from host scopes.
func cacheRegistry(ctx context.Context, host string) string {
	repos := repositoriesForHost(ctx, host)
	if len(repos) == 0 {
		return host
	}

	// ORAS caches scheme and Basic credentials by registry
	// and can send cached Basic credentials before a new challenge.
	// Exact repositories, rather than matched auth keys,
	// also prevent reuse of Bearer tokens with narrower scopes.
	// NUL and unit-separator cannot collide with normal registry/path names.
	return host + "\x00repos=" + strings.Join(repos, "\x1f")
}
