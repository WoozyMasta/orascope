// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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

// TestWrapAuthClientIsIdempotentWithoutCache verifies nil cache remains disabled.
func TestWrapAuthClientIsIdempotentWithoutCache(t *testing.T) {
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	client := &auth.Client{
		Credential: func(context.Context, string) (auth.Credential, error) {
			calls++
			return auth.Credential{Username: "user", Password: "password"}, nil
		},
	}
	first, err := adapter.WrapAuthClient(client)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.WrapAuthClient(first)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("wrapped client was cloned twice")
	}
	cacheCalls := 0
	for range 2 {
		if _, err := second.Cache.Set(
			context.Background(), "registry.test", auth.SchemeBasic, "",
			func(context.Context) (string, error) {
				cacheCalls++
				return "token", nil
			}); err != nil {
			t.Fatal(err)
		}
	}
	if cacheCalls != 2 {
		t.Fatalf("disabled cache reused a token %d times", cacheCalls)
	}
	if _, err := second.Credential(context.Background(), "registry.test"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("fallback called %d times", calls)
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

// TestConvertEntryCombinesCredentialForms verifies ORAS-compatible field preservation.
func TestConvertEntryCombinesCredentialForms(t *testing.T) {
	credential, err := convertEntry(authEntry{
		Auth:          base64.StdEncoding.EncodeToString([]byte("auth-user:auth-password")),
		Username:      "explicit-user",
		Password:      "explicit-password",
		IdentityToken: "refresh-token",
		RegistryToken: "access-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	if credential.Username != "auth-user" || credential.Password != "auth-password" {
		t.Fatalf("unexpected Basic credential: %#v", credential)
	}
	if credential.RefreshToken != "refresh-token" || credential.AccessToken != "access-token" {
		t.Fatalf("unexpected token credential: %#v", credential)
	}
}

// TestGuardMountFromFiltersCandidatesByDestinationPrincipal verifies relative mount paths.
func TestGuardMountFromFiltersCandidatesByDestinationPrincipal(t *testing.T) {
	adapter, err := New(WithDockerAuthConfigJSON([]byte(`{"auths":{
		"registry.test/team":{"auth":"dGVhbTp0ZWFt"},
		"registry.test/other":{"auth":"b3RoZXI6b3RoZXI="}
	}}`)))
	if err != nil {
		t.Fatal(err)
	}

	guard := adapter.GuardMountFrom(
		registry.Reference{Registry: "registry.test", Repository: "team/destination"},
		func(context.Context, ocispec.Descriptor) ([]string, error) {
			return []string{"team/source", "other/source"}, nil
		},
	)
	candidates, err := guard(context.Background(), ocispec.Descriptor{})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != "team/source" {
		t.Fatalf("unexpected mount candidates: %#v", candidates)
	}
}

// TestAppendEncodedConfigRejectsConflictingAliases verifies alias conflict handling.
func TestAppendEncodedConfigRejectsConflictingAliases(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte(`{"auths":{}}`))
	second := base64.StdEncoding.EncodeToString([]byte(`{"auths":{"registry.test":{}}}`))
	t.Setenv("DOCKER_AUTH_CONFIG_BASE64", first)
	t.Setenv("DOCKER_AUTH_CONFIG_ENCODED", second)

	_, err := appendEncodedConfig(nil)
	if !errors.Is(err, ErrConflictingEncodedAuthConfig) {
		t.Fatalf("got %v", err)
	}
}

// TestAppendEncodedConfigAcceptsEquivalentAliases verifies aliases add one source.
func TestAppendEncodedConfigAcceptsEquivalentAliases(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"auths":{}}`))
	t.Setenv("DOCKER_AUTH_CONFIG_BASE64", encoded)
	t.Setenv("DOCKER_AUTH_CONFIG_ENCODED", encoded)

	inputs, err := appendEncodedConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 1 || inputs[0].id != "env:DOCKER_AUTH_CONFIG_BASE64" {
		t.Fatalf("unexpected encoded inputs: %#v", inputs)
	}
}

// TestSourceHostCredentialUsesHelper verifies helpers receive only the registry host.
func TestSourceHostCredentialUsesHelper(t *testing.T) {
	helperDirectory := t.TempDir()
	helperName := "docker-credential-orascope-test"
	helperPath := filepath.Join(helperDirectory, helperName)
	if runtime.GOOS == "windows" {
		helperPath += ".exe"
	}
	sourcePath := filepath.Join(helperDirectory, "main.go")
	helperSource := `package main
import (
 "fmt"
 "io"
 "os"
)
func main() {
 input, _ := io.ReadAll(os.Stdin)
 if string(input) != "registry.test" { os.Exit(2) }
 fmt.Print(` + "`" + `{"Username":"helper-user","Secret":"helper-password"}` + "`" + `)
}`
	if err := os.WriteFile(sourcePath, []byte(helperSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", helperPath, sourcePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v: %s", err, output)
	}
	t.Setenv("PATH", helperDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))

	source := source{helpers: map[string]string{"registry.test": "orascope-test"}}
	credential, err := source.hostCredential(context.Background(), "registry.test")
	if err != nil {
		t.Fatal(err)
	}
	if credential.Username != "helper-user" || credential.Password != "helper-password" {
		t.Fatalf("unexpected helper credential: %#v", credential)
	}
}

// TestScopedBasicAuthenticationDoesNotLeakAcrossRepositories verifies cache isolation.
func TestScopedBasicAuthenticationDoesNotLeakAcrossRepositories(t *testing.T) {
	users := map[string]struct {
		username string
		password string
	}{
		"org-a": {username: "user-a", password: "password-a"},
		"org-b": {username: "user-b", password: "password-b"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
		if len(parts) < 4 || parts[0] != "v2" || parts[2] != "app" {
			http.NotFound(writer, request)
			return
		}
		expected, ok := users[parts[1]]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != expected.username || password != expected.password {
			writer.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"tags":[]}`))
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "http://")
	config := fmt.Sprintf(`{"auths":{
		%q:{"auth":%q},
		%q:{"auth":%q}
	}}`,
		host+"/org-a", base64.StdEncoding.EncodeToString([]byte("user-a:password-a")),
		host+"/org-b", base64.StdEncoding.EncodeToString([]byte("user-b:password-b")))
	adapter, err := New(WithDockerAuthConfigJSON([]byte(config)))
	if err != nil {
		t.Fatal(err)
	}

	for _, repository := range []string{"org-a/app", "org-b/app", "org-a/app", "org-b/app"} {
		repo, err := remote.NewRepository(host + "/" + repository)
		if err != nil {
			t.Fatal(err)
		}
		repo.PlainHTTP = true
		if err := adapter.WrapRepository(repo); err != nil {
			t.Fatal(err)
		}
		if err := repo.Tags(context.Background(), "", func([]string) error { return nil }); err != nil {
			t.Fatalf("list tags for %s: %v", repository, err)
		}
	}
}
