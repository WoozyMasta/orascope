# ORAScope

ORAScope adds repository path scoped credential resolution to
[`oras-go/v2`](https://oras.land/oras-go/v2/).

ORAS resolves credentials by registry host.
This is insufficient when one registry
uses different credentials for separate namespaces,
for example `registry.example.com/team-a` and `registry.example.com/team-b`.

ORAScope selects the most specific matching inline `auths` entry
for the repository being requested, while leaving ORAS responsible
for Basic, Bearer and OAuth2 authentication flows.

For `registry.example.com/team-a/project/image`,
credentials are checked in this order:

* `registry.example.com/team-a/project/image`
* `registry.example.com/team-a/project`
* `registry.example.com/team-a`
* normal host-level resolution for `registry.example.com`

## Installation

```sh
go get github.com/woozymasta/orascope
```

## Usage

Configure repository-scoped credentials through a Docker-compatible source:

```json
{
  "auths": {
    "registry.example.com/team-a": {
      "auth": "<base64-username-colon-password>"
    },
    "registry.example.com/team-b": {
      "auth": "<base64-username-colon-password>"
    }
  }
}
```

Then wrap an ORAS repository before using it:

```go
package main

import (
    "context"
    "log"

    "github.com/woozymasta/orascope"
    "oras.land/oras-go/v2/registry/remote"
)

func main() {
    ctx := context.Background()

    adapter, err := orascope.NewDefault()
    if err != nil {
        log.Fatal(err)
    }

    repo, err := remote.NewRepository("registry.example.com/team-a/app")
    if err != nil {
        log.Fatal(err)
    }
    if err := adapter.WrapRepository(repo); err != nil {
        log.Fatal(err)
    }

    if err := repo.Tags(ctx, "", func(tags []string) error {
        return nil
    }); err != nil {
        log.Fatal(err)
    }
}
```

`NewDefault` reads a snapshot of these sources, in order:
`DOCKER_AUTH_CONFIG`, Docker config, containers auth files,
legacy `.dockercfg`, and encoded Docker config environment variables.
Recreate the adapter after changing a config.

## Important details

* Scoped inline `auths` always win over any host-only credential,
  regardless of source priority. Equal scoped paths use source priority.
* `credHelpers` and `credsStore` stay host-scoped;
  ORAScope never invokes a helper with `registry.example.com/team-a`.
* The wrapped client remains `*auth.Client`,
  so ORAS retains its authentication, token, retry and redirect behavior.
  Its cache is namespaced by repository to avoid reusing Basic
  or Bearer state across sibling namespaces.
* A request covering multiple repositories fails with
  `ErrAmbiguousRepositoryCredentials` if their resolved principals differ.
  For `oras.CopyGraphOptions.MountFrom`, use `Adapter.GuardMountFrom` to filter
  incompatible mount candidates and let ORAS fall back to regular copy.
