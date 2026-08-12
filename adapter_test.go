// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// TestScopedCredentialSelection verifies specificity and path-segment isolation
func TestScopedCredentialSelection(t *testing.T) {
	a, err := New(WithDockerAuthConfigJSON([]byte(`{"auths":{
	"registry.test":{"auth":"aG9zdDpob3N0"},
	"registry.test/org":{"auth":"b3JnOm9yZw=="},
	"registry.test/org/app":{"auth":"YXBwOmFwcA=="}
}}`)))
	if err != nil {
		t.Fatal(err)
	}

	ctx := auth.AppendRepositoryScope(
		context.Background(),
		registry.Reference{Registry: "registry.test", Repository: "org/app/image"},
		auth.ActionPull)
	cred, err := a.CredentialFunc(nil)(ctx, "registry.test")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "app" || cred.Password != "app" {
		t.Fatalf("got %#v", cred)
	}

	ctx = auth.AppendRepositoryScope(
		context.Background(),
		registry.Reference{Registry: "registry.test", Repository: "org-admin/image"},
		auth.ActionPull)
	cred, err = a.CredentialFunc(nil)(ctx, "registry.test")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Username != "host" {
		t.Fatalf("prefix collision: %#v", cred)
	}
}

// TestScopedBeatsSourcePriorityAndMultiRepositoryFailsClosed verifies policy ordering
func TestScopedBeatsSourcePriorityAndMultiRepositoryFailsClosed(t *testing.T) {
	a, err := New(
		WithDockerAuthConfigJSON([]byte(`{"auths":{"registry.test":{"auth":"aG9zdDpob3N0"}}}`)),
		WithDockerAuthConfigJSON([]byte(`{"auths":{
	"registry.test/org":{"auth":"c2NvcGVkOnNjb3BlZA=="},
	"registry.test/other":{"auth":"b3RoZXI6b3RoZXI="}
}}`)),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := auth.AppendRepositoryScope(
		context.Background(),
		registry.Reference{Registry: "registry.test", Repository: "org/image"},
		auth.ActionPull)
	cred, err := a.CredentialFunc(nil)(ctx, "registry.test")
	if err != nil || cred.Username != "scoped" {
		t.Fatalf("got %#v, %v", cred, err)
	}

	ctx = auth.AppendRepositoryScope(
		ctx,
		registry.Reference{Registry: "registry.test", Repository: "other/image"},
		auth.ActionPull,
	)
	_, err = a.CredentialFunc(nil)(ctx, "registry.test")
	if !errors.Is(err, ErrAmbiguousRepositoryCredentials) {
		t.Fatalf("got %v", err)
	}
}

// TestCacheIsolatedByRepository verifies sibling repository cache isolation
func TestCacheIsolatedByRepository(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}

	cache := a.Cache(auth.NewCache())
	ctxA := auth.AppendRepositoryScope(
		context.Background(),
		registry.Reference{Registry: "registry.test", Repository: "org-a/image"},
		auth.ActionPull)
	ctxB := auth.AppendRepositoryScope(
		context.Background(),
		registry.Reference{Registry: "registry.test", Repository: "org-b/image"},
		auth.ActionPull)

	if _, err := cache.Set(
		ctxA, "registry.test", auth.SchemeBasic, "",
		func(context.Context) (string, error) { return "token-a", nil },
	); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetToken(
		ctxB, "registry.test", auth.SchemeBasic, "",
	); err == nil {
		t.Fatal("token leaked to sibling repository")
	}
	if token, err := cache.GetToken(
		ctxA, "registry.test", auth.SchemeBasic, "",
	); err != nil || token != "token-a" {
		t.Fatalf("got %q, %v", token, err)
	}
}

// TestWrapRepositoryKeepsAuthClient verifies cloning preserves the client type
func TestWrapRepositoryKeepsAuthClient(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}

	original := &auth.Client{
		Header: map[string][]string{"X-Test": {"value"}},
		Cache:  auth.NewCache(),
	}
	repo := &remote.Repository{Client: original}

	if err := a.WrapRepository(repo); err != nil {
		t.Fatal(err)
	}
	wrapped, ok := repo.Client.(*auth.Client)
	if !ok || wrapped == original {
		t.Fatal("client was not cloned as *auth.Client")
	}
	wrapped.Header.Set("X-Test", "changed")
	if original.Header.Get("X-Test") != "value" {
		t.Fatal("header map was mutated")
	}
}

// TestConvertEntryPasswordWithColon verifies auth decoding preserves colon data
func TestConvertEntryPasswordWithColon(t *testing.T) {
	value := base64.StdEncoding.EncodeToString([]byte("user:pass:word"))
	cred, err := convertEntry(authEntry{Auth: value})
	if err != nil || cred.Username != "user" || cred.Password != "pass:word" {
		t.Fatalf("got %#v, %v", cred, err)
	}
}
