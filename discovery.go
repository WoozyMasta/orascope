// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// appendDiscovery appends automatic sources after explicit higher-priority sources.
func appendDiscovery(explicit []inputSource) ([]inputSource, error) {
	// Append in documented priority order.
	// Scoped specificity is applied later and deliberately outranks this source order.
	inputs := append([]inputSource(nil), explicit...)
	if value, ok := os.LookupEnv("DOCKER_AUTH_CONFIG"); ok {
		inputs = append(inputs, inputSource{id: "env:DOCKER_AUTH_CONFIG", data: []byte(value)})
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}

	docker := filepath.Join(home, ".docker", "config.json")
	if directory := os.Getenv("DOCKER_CONFIG"); directory != "" {
		docker = filepath.Join(directory, "config.json")
	}

	inputs = appendOptional(inputs, "docker-config", docker, false)
	if path := os.Getenv("REGISTRY_AUTH_FILE"); path != "" {
		inputs = appendOptional(inputs, "registry-auth-file", path, true)
	} else if runtime.GOOS == "linux" && os.Getenv("XDG_RUNTIME_DIR") != "" {
		inputs = appendOptional(
			inputs,
			"containers-runtime",
			filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "containers", "auth.json"),
			false)
	} else {
		inputs = appendOptional(
			inputs,
			"containers-primary",
			filepath.Join(home, ".config", "containers", "auth.json"),
			false)
	}

	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = filepath.Join(home, ".config")
	}

	inputs = appendOptional(
		inputs,
		"containers-persistent",
		filepath.Join(xdg, "containers", "auth.json"),
		false)
	inputs = appendOptional(
		inputs,
		"dockercfg",
		filepath.Join(home, ".dockercfg"),
		false)

	inputs, err = appendEncodedConfig(inputs)
	if err != nil {
		return nil, err
	}

	return deduplicatePaths(inputs), nil
}

// appendEncodedConfig adds the single validated encoded environment source.
func appendEncodedConfig(inputs []inputSource) ([]inputSource, error) {
	first, firstOK := os.LookupEnv("DOCKER_AUTH_CONFIG_BASE64")
	second, secondOK := os.LookupEnv("DOCKER_AUTH_CONFIG_ENCODED")
	if !firstOK && !secondOK {
		return inputs, nil
	}

	var data []byte
	if firstOK {
		decoded, err := decodeConfig(first)
		if err != nil {
			return nil, err
		}
		data = decoded
	}

	if secondOK {
		decoded, err := decodeConfig(second)
		if err != nil {
			return nil, err
		}
		if firstOK && string(data) != string(decoded) {
			// The aliases describe one source, so conflicting payloads are ambiguous.
			return nil, ErrConflictingEncodedAuthConfig
		}
		data = decoded
	}

	return append(inputs, inputSource{id: "env:DOCKER_AUTH_CONFIG_BASE64", data: data}), nil
}

// appendOptional adds a present optional file or a required configured path.
func appendOptional(inputs []inputSource, id, path string, required bool) []inputSource {
	if path == "" {
		return inputs
	}

	//nolint:gosec // The path is either a documented environment location or caller option.
	if _, err := os.Stat(path); err == nil {
		return append(inputs, inputSource{id: "file:" + id, path: path})
	}
	if required {
		// An explicit environment override is a configuration error if unreadable;
		// absent default locations are intentionally optional.
		return append(inputs, inputSource{id: "file:" + id, path: path})
	}

	return inputs
}

// deduplicatePaths canonicalizes and removes repeated configuration paths.
func deduplicatePaths(inputs []inputSource) []inputSource {
	seen := map[string]bool{}
	output := make([]inputSource, 0, len(inputs))
	for _, input := range inputs {
		if input.path != "" {
			absolute, err := filepath.Abs(input.path)
			if err == nil {
				input.path = filepath.Clean(absolute)
			}
			if seen[input.path] {
				continue
			}

			seen[input.path] = true
		}
		output = append(output, input)
	}

	return output
}

// decodeConfig decodes and validates a standard-base64 Docker config payload.
func decodeConfig(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(value))
	}
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("%w: invalid encoded configuration", ErrInvalidAuthConfig)
	}

	var document json.RawMessage
	if json.Unmarshal(data, &document) != nil {
		return nil, fmt.Errorf("%w: invalid encoded configuration", ErrInvalidAuthConfig)
	}

	return data, nil
}
