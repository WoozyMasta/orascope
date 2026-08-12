// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// scopedCache applies a repository-scope namespace to an ORAS cache.
type scopedCache struct {
	// base stores the namespaced cache records.
	base auth.Cache
}

// Cache namespaces an ORAS cache by the exact repository scopes in context.
func (a *Adapter) Cache(base auth.Cache) auth.Cache {
	if base == nil {
		return nil
	}
	if _, ok := base.(*scopedCache); ok {
		return base
	}
	return &scopedCache{base: base}
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
