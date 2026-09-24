# Encrypted file keyring backend

This is a simple keyring backend, that stores/uses secrets in encrypted
files.

## Details

It supports multiple keyrings.

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the documentation of the individual methods.

## See also

Other keyring backends:
[`backend_env`](https://keyring.r-lib.org/dev/reference/backend_env.md),
[`backend_macos`](https://keyring.r-lib.org/dev/reference/backend_macos.md),
[`backend_secret_service`](https://keyring.r-lib.org/dev/reference/backend_secret_service.md),
[`backend_wincred`](https://keyring.r-lib.org/dev/reference/backend_wincred.md)

## Examples

``` r
if (FALSE) { # \dontrun{
kb <- backend_file$new()
} # }
```
