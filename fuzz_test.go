// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzConvertAuthEntry verifies config auth decoding is panic-free and stable.
func FuzzConvertAuthEntry(f *testing.F) {
	f.Add("")
	f.Add(base64.StdEncoding.EncodeToString([]byte("user:password")))
	f.Add(base64.StdEncoding.EncodeToString([]byte("user:password:with:colon")))
	f.Add("not-base64")
	f.Add(base64.StdEncoding.EncodeToString([]byte("missing-separator")))

	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = convertEntry(authEntry{Auth: encoded})
	})
}

// FuzzHierarchy verifies generated scoped keys stay exact and segment-safe.
func FuzzHierarchy(f *testing.F) {
	f.Add("registry.example.com", "org/project/image")
	f.Add("registry.example.com:5000", "org/image")
	f.Add("registry.example.com", "")
	f.Add("registry.example.com", "/org/project/image/")

	f.Fuzz(func(t *testing.T, host, repository string) {
		keys := candidates(host, repository)
		previous := ""
		for _, key := range keys {
			if key == "" || strings.HasSuffix(key, "/") {
				t.Fatalf("invalid candidate %q", key)
			}
			if previous != "" && !strings.HasPrefix(previous, key+"/") {
				t.Fatalf("candidate %q is not parent of %q", key, previous)
			}
			previous = key
		}
	})
}
