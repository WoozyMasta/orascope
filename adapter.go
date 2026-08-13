// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"fmt"
	"net/http"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Adapter resolves path-scoped inline credentials without replacing ORAS auth.
type Adapter struct {
	fallback auth.CredentialFunc // fallback is the final caller-provided host-level credential resolver.
	sources  []source            // sources is the immutable precedence-ordered configuration snapshot.
}

// New creates an immutable adapter from explicit and automatically discovered sources.
// WithoutDiscovery limits it to explicit sources.
func New(opts ...Option) (*Adapter, error) {
	options := options{discover: true}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	inputs := options.sources
	if options.discover {
		var err error
		inputs, err = appendDiscovery(options.sources)
		if err != nil {
			return nil, err
		}
	}

	sources := make([]source, 0, len(inputs))
	for _, input := range inputs {
		source, err := loadSource(input)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}

	return &Adapter{sources: sources, fallback: options.fallback}, nil
}

// NewDefault creates an adapter using the documented environment discovery.
func NewDefault() (*Adapter, error) {
	return New()
}

// CredentialFunc returns a context-aware credential resolver.
func (a *Adapter) CredentialFunc(fallback auth.CredentialFunc) auth.CredentialFunc {
	return func(ctx context.Context, host string) (auth.Credential, error) {
		// ORAS only passes host to CredentialFunc.
		// Repository identity must be taken per request from context scopes,
		// not captured from a repository during wrapping:
		// ORAS may use the same client for sibling repositories.
		repos := repositoriesForHost(ctx, host)
		if len(repos) == 0 {
			// Registry-level operations have no repository identity to scope.
			return a.hostCredential(ctx, host, fallback)
		}

		matches := make([]resolvedCredential, 0, len(repos))
		for _, repo := range repos {
			matches = append(matches, a.resolve(ctx, host, repo, fallback))
		}
		first := matches[0]
		for _, match := range matches[1:] {
			if match.principal != first.principal {
				// One request cannot safely authenticate as two independent principals.
				// Principal is source/key metadata, rather than credential comparison,
				// so this decision never relies on or exposes secret material.
				return auth.EmptyCredential, fmt.Errorf(
					"%w for %s repositories %s and %s",
					ErrAmbiguousRepositoryCredentials, host, repos[0], repos[len(repos)-1])
			}
		}

		return first.credential, first.err
	}
}

// GuardMountFrom filters mount candidates that need a different principal.
func (a *Adapter) GuardMountFrom(
	destination registry.Reference,
	next func(context.Context, ocispec.Descriptor) ([]string, error),
) func(context.Context, ocispec.Descriptor) ([]string, error) {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]string, error) {
		candidates, err := next(ctx, desc)
		if err != nil {
			return nil, err
		}

		destinationMatch := a.resolve(ctx, destination.Registry, destination.Repository, nil)
		if destinationMatch.err != nil {
			return nil, destinationMatch.err
		}

		allowed := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			ref := registry.Reference{
				Registry:   destination.Registry,
				Repository: candidate,
			}
			if err := ref.ValidateRepository(); err != nil {
				return nil, fmt.Errorf("invalid mount candidate %q: %w", candidate, err)
			}

			// ORAS MountFrom returns repository names relative to the destination registry, not full references.
			// ParseReference would treat the first path segment as a registry and reject valid mount candidates.
			match := a.resolve(ctx, destination.Registry, candidate, nil)
			if match.err != nil {
				return nil, match.err
			}

			if match.principal == destinationMatch.principal {
				// Keep only candidates authorized by the destination principal.
				allowed = append(allowed, candidate)
			}
		}

		return allowed, nil
	}
}

// WrapAuthClient clones client and installs resolver and cache wrappers.
func (a *Adapter) WrapAuthClient(client *auth.Client) (*auth.Client, error) {
	if client == nil {
		client = auth.DefaultClient
	}
	if cache, ok := client.Cache.(*scopedCache); ok && cache.adapter == a {
		return client, nil // A no-op cache preserves nil-cache semantics while providing this marker.
	}

	clone := *client
	// Preserve *auth.Client instead of wrapping remote.Client:
	// ORAS detects this concrete type to retain authenticated retry
	// and manifest-body handling.
	clone.Header = client.Header.Clone()
	clone.Credential = a.CredentialFunc(client.Credential)
	clone.Cache = a.Cache(client.Cache)

	return &clone, nil
}

// WrapRepository installs a cloned *auth.Client on repo.
func (a *Adapter) WrapRepository(repo *remote.Repository) error {
	if repo == nil {
		return ErrNilRepository
	}

	if repo.Client == nil {
		client, err := a.WrapAuthClient(auth.DefaultClient)
		if err != nil {
			return err
		}
		repo.Client = client
		return nil
	}

	if client, ok := repo.Client.(*auth.Client); ok {
		wrapped, err := a.WrapAuthClient(client)
		if err != nil {
			return err
		}
		repo.Client = wrapped
		return nil
	}

	if client, ok := repo.Client.(*http.Client); ok {
		wrapped, err := a.WrapAuthClient(&auth.Client{Client: client, Cache: auth.NewCache()})
		if err != nil {
			return err
		}
		repo.Client = wrapped
		return nil
	}

	return fmt.Errorf("%w: %T", ErrUnsupportedClient, repo.Client)
}

// WrapRegistry installs a cloned *auth.Client in repository options.
func (a *Adapter) WrapRegistry(registryClient *remote.Registry) error {
	if registryClient == nil {
		return ErrNilRegistry
	}

	repo := &remote.Repository{Client: registryClient.Client}
	if err := a.WrapRepository(repo); err != nil {
		return err
	}

	registryClient.Client = repo.Client
	return nil
}
