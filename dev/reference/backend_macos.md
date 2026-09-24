# macOS Keychain keyring backend

This backend is the default on macOS. It uses the macOS native Keychain
Service API.

## Details

It supports multiple keyrings.

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the documentation of the individual methods.

## See also

Other keyring backends:
[`backend_env`](https://keyring.r-lib.org/dev/reference/backend_env.md),
[`backend_file`](https://keyring.r-lib.org/dev/reference/backend_file.md),
[`backend_secret_service`](https://keyring.r-lib.org/dev/reference/backend_secret_service.md),
[`backend_wincred`](https://keyring.r-lib.org/dev/reference/backend_wincred.md)

## Examples

``` r
if (FALSE) { # \dontrun{
## This only works on macOS
kb <- backend_macos$new()
kb$keyring_create("foobar")
kb$set_default_keyring("foobar")
kb$set_with_value("service", password = "secret")
kb$get("service")
kb$delete("service")
kb$delete_keyring("foobar")
} # }
```
