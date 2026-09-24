# Environment variable keyring backend

This is a simple keyring backend, that stores/uses secrets in
environment variables of the R session.

## Details

It does not support multiple keyrings. It also does not support listing
all keys, since there is no way to distinguish keys from regular
environment variables.

It does support service names and usernames: they will be separated with
a `:` character in the name of the environment variable. (Note that such
an environment variable typically cannot be set or queried from a shell,
but it can be set and queried from R or other programming languages.)

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the documentation of the class's methods.

## See also

Other keyring backends:
[`backend_file`](https://keyring.r-lib.org/dev/reference/backend_file.md),
[`backend_macos`](https://keyring.r-lib.org/dev/reference/backend_macos.md),
[`backend_secret_service`](https://keyring.r-lib.org/dev/reference/backend_secret_service.md),
[`backend_wincred`](https://keyring.r-lib.org/dev/reference/backend_wincred.md)

## Examples

``` r
if (FALSE) { # \dontrun{
env <- backend_env$new()
env$set("r-keyring-test", username = "donaldduck")
env$get("r-keyring-test", username = "donaldduck")
Sys.getenv("r-keyring-test:donaldduck")

# This is an error
env$list()

# Clean up
env$delete("r-keyring-test", username = "donaldduck")
} # }
```
