# Linux Secret Service keyring backend

This backend is the default on Linux. It uses the libsecret library, and
needs a secret service daemon running (e.g. Gnome Keyring, or KWallet).
It uses DBUS to communicate with the secret service daemon.

## Details

This backend supports multiple keyrings.

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the documentation of the individual methods. The `is_available()` method
checks is a Secret Service daemon is running on the system, by trying to
connect to it. It returns a logical scalar, or throws an error,
depending on its argument:

    is_available = function(report_error = FALSE)

Argument:

- `report_error` Whether to throw an error if the Secret Service is not
  available.

## See also

Other keyring backends:
[`backend_env`](https://keyring.r-lib.org/dev/reference/backend_env.md),
[`backend_file`](https://keyring.r-lib.org/dev/reference/backend_file.md),
[`backend_macos`](https://keyring.r-lib.org/dev/reference/backend_macos.md),
[`backend_wincred`](https://keyring.r-lib.org/dev/reference/backend_wincred.md)

## Examples

``` r
if (FALSE) { # \dontrun{
## This only works on Linux, typically desktop Linux
kb <- backend_secret_service$new()
kb$keyring_create("foobar")
kb$set_default_keyring("foobar")
kb$set_with_value("service", password = "secret")
kb$get("service")
kb$delete("service")
kb$delete_keyring("foobar")
} # }
```
