# Windows Credential Store keyring backend

This backend is the default on Windows. It uses the native Windows
Credential API, and needs at least Windows XP to run.

## Details

This backend supports multiple keyrings. Note that multiple keyrings are
implemented in the `keyring` R package, using some dummy keyring keys
that represent keyrings and their locked/unlocked state.

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the documentation of the individual methods.

## See also

Other keyring backends:
[`backend_env`](https://keyring.r-lib.org/dev/reference/backend_env.md),
[`backend_file`](https://keyring.r-lib.org/dev/reference/backend_file.md),
[`backend_macos`](https://keyring.r-lib.org/dev/reference/backend_macos.md),
[`backend_secret_service`](https://keyring.r-lib.org/dev/reference/backend_secret_service.md)

## Examples

``` r
if (FALSE) { # \dontrun{
## This only works on Windows
kb <- backend_wincred$new()
kb$keyring_create("foobar")
kb$set_default_keyring("foobar")
kb$set_with_value("service", password = "secret")
kb$get("service")
kb$delete("service")
kb$delete_keyring("foobar")
} # }
```
