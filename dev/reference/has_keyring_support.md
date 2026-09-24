# Operations on keyrings

On most platforms `keyring` supports multiple keyrings. This includes
Windows, macOS and Linux (Secret Service) as well. A keyring is a
collection of keys that can be treated as a unit. A keyring typically
has a name and a password to unlock it. Once a keyring is unlocked, it
remains unlocked until the end of the user session, or until it is
explicitly locked again.

## Usage

``` r
has_keyring_support()

keyring_create(keyring, password = NULL)

keyring_list()

keyring_delete(keyring = NULL)

keyring_lock(keyring = NULL)

keyring_unlock(keyring = NULL, password = NULL)

keyring_is_locked(keyring = NULL)
```

## Arguments

- keyring:

  The name of the keyring to create or to operate on. For functions
  other than `keyring_create`, it can also be `NULL` to select the
  default keyring.

- password:

  The initial password or the password to unlock the keyring. If not
  specified or `NULL`, it will be read from the console.

## Details

Platforms typically have a default keyring, which is unlocked
automatically when the user logs in. This keyring does not need to be
unlocked explicitly.

You can configure the keyring to use via R options or environment
variables (see
[`default_backend()`](https://keyring.r-lib.org/dev/reference/backends.md)),
or you can also specify it directly in the
[`default_backend()`](https://keyring.r-lib.org/dev/reference/backends.md)
call, or in the individual `keyring` calls.

`has_keyring_support` checks if a backend supports multiple keyrings.

`keyring_create` creates a new keyring. It asks for a password if no
password is specified.

`keyring_list` lists all existing keyrings.

`keyring_delete` deletes a keyring. Deleting a non-empty keyring
requires confirmation, and the default keyring can only be deleted if
specified explicitly. On some backends (e.g. Windows Credential Store),
the default keyring cannot be deleted at all.

`keyring_lock` locks a keyring. On some backends (e.g. Windows
Credential Store), the default keyring cannot be locked.

`keyring_unlock` unlocks a keyring. If a password is not specified, it
will be read in interactively.

`keyring_is_locked` queries whether a keyring is locked.

## Examples

``` r
default_backend()
#> Warning: Selecting ‘env’ backend. Secrets are stored in environment variables
#> <keyring backend: ‘env’>
#> Store secrets in environment variables.
#> 
#>  $get                  query a key from the keyring
#>  $set                  set a key in the keyring (interactive)
#>  $set_with_value       set a key in the keyring
#>  $delete               delete a key
#>  $list                 list keys in a keyring
#>  $list_raw             list keys in a keyring as raw vectors
#>  $has_keyring_support  TRUE if multiple keyrings are supported
has_keyring_support()
#> Warning: Selecting ‘env’ backend. Secrets are stored in environment variables
#> [1] FALSE
backend_env$new()$has_keyring_support()
#> [1] FALSE

## This might ask for a password, so we do not run it by default
## It only works if the default backend supports multiple keyrings
if (FALSE) { # \dontrun{
keyring_create("foobar")
key_set_with_value("R-test-service", "donaldduck", password = "secret",
                   keyring = "foobar")
key_get("R-test-service", "donaldduck", keyring = "foobar")
key_list(keyring = "foobar")
keyring_delete(keyring = "foobar")
} # }
```
