// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import "oras.land/oras-go/v2/registry/remote/auth"

// Option configures Adapter construction.
type Option func(*options) error

// options accumulates explicit sources before discovery.
type options struct {
	fallback auth.CredentialFunc // fallback is the final host-level resolver.
	sources  []inputSource       // sources is the precedence-ordered explicit source list.
}

// inputSource identifies either in-memory configuration bytes or a file path.
type inputSource struct {
	id   string // id is a non-secret diagnostic identifier.
	path string // path is the configuration file path.
	data []byte // data is raw in-memory JSON configuration.
}

// WithDockerAuthConfigJSON adds an explicit Docker-compatible JSON source.
func WithDockerAuthConfigJSON(data []byte) Option {
	return func(options *options) error {
		options.sources = append(
			options.sources,
			inputSource{id: "option:docker-auth-config", data: append([]byte(nil), data...)})

		return nil
	}
}

// WithDockerAuthConfigBase64 adds an explicit base64-encoded JSON source.
func WithDockerAuthConfigBase64(value string) Option {
	return func(options *options) error {
		data, err := decodeConfig(value)
		if err != nil {
			return err
		}

		options.sources = append(
			options.sources,
			inputSource{id: "option:docker-auth-config-base64", data: data})

		return nil
	}
}

// WithDockerConfigPath adds an explicit Docker config file.
func WithDockerConfigPath(path string) Option {
	return withPath("option:docker-config", path)
}

// WithContainersAuthPath adds an explicit containers auth file.
func WithContainersAuthPath(path string) Option {
	return withPath("option:containers-auth", path)
}

// WithAdditionalConfig adds an explicit compatible config file.
func WithAdditionalConfig(path string) Option {
	return withPath("option:additional-config", path)
}

// withPath creates an option for an explicit configuration path.
func withPath(id, path string) Option {
	return func(options *options) error {
		options.sources = append(options.sources, inputSource{id: id, path: path})
		return nil
	}
}

// WithCredentialFallback adds a final host-level fallback.
func WithCredentialFallback(fn auth.CredentialFunc) Option {
	return func(options *options) error { options.fallback = fn; return nil }
}
