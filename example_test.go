// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright 2026 WoozyMasta
// Source: github.com/woozymasta/orascope

package orascope_test

import (
	"fmt"

	"github.com/woozymasta/orascope"
	"oras.land/oras-go/v2/registry/remote"
)

// ExampleAdapter_WrapRepository configures a repository for scoped auth.
func ExampleAdapter_WrapRepository() {
	adapter, err := orascope.New(
		orascope.WithDockerAuthConfigJSON([]byte(`{
			"auths": {
				"registry.example.com/team-a": {
					"auth": "dXNlcjpwYXNzd29yZA=="
				}
			}
		}`)),
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	repo, err := remote.NewRepository("registry.example.com/team-a/application")
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := adapter.WrapRepository(repo); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%T\n", repo.Client)
	// Output:
	// *auth.Client
}
