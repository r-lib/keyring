# Operations on keys

These functions manipulate keys in a keyring. You can think of a keyring
as a secure key-value store.

## Usage

``` r
key_get(service, username = NULL, keyring = NULL)

key_get_raw(service, username = NULL, keyring = NULL)

key_set(service, username = NULL, keyring = NULL, prompt = "Password: ")

key_set_with_value(service, username = NULL, password = NULL, keyring = NULL)

key_set_with_raw_value(
  service,
  username = NULL,
  password = NULL,
  keyring = NULL
)

key_delete(service, username = NULL, keyring = NULL)

key_list(service = NULL, keyring = NULL)

key_list_raw(service = NULL, keyring = NULL)
```

## Arguments

- service:

  Service name, a character scalar.

- username:

  Username, a character scalar, or `NULL` if the key is not associated
  with a username.

- keyring:

  For systems that support multiple keyrings, specify the name of the
  keyring to use here. If `NULL`, then the default keyring is used. See
  also
  [`has_keyring_support()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md).

- prompt:

  The character string displayed when requesting the secret

- password:

  The secret to store. For `key_set`, it is read from the console,
  interactively. `key_set_with_value` can be also used in
  non-interactive mode.

## Value

`key_get` returns a character scalar, the password or other confidential
information that was stored in the key.

`key_list` returns a list of keys, i.e. service names and usernames, in
a data frame with column names `service` and `username`. If a service or
user name contains a zero byte, which is not allowed in an R string,
that entry is shown as `NA` and a warning (of class
`keyring_warn_zero_byte_keys`) is thrown. You can use the
`key_list_raw()` function to query these keys.

`key_list_raw` is similar to `key_list` but returns service and
usernames as raw vectors. This is useful if some service or user names)
contain zero bytes. All column names: `service`, `username`,
`service_raw`, `username_raw`.

## Details

`key_get` queries a key from the keyring.

`key_get_raw` queries a key and returns it as a raw vector. Most
credential stores allow storing a byte sequence with embedded null
bytes, and these cannot be represented as traditional null bytes
terminated strings. If you don't know whether the key contains an
embedded null, it is best to query it with `key_get_raw` instead of
`key_get`.

`key_set` sets a key in the keyring. The contents of the key is read
interactively from the terminal.

`key_set_with_value` is the non-interactive pair of `key_set`, to set a
key in the keyring.

`key_set_raw_with_value` sets a key to a byte sequence from a raw
vector.

`key_delete` deletes a key.

`key_list` lists all keys of a keyring, or the keys for a certain
service (if `service` is not `NULL`). Note that `key_list` cannot access
keys that are created by another software. To access such keys see the
`{oskeyring}` package instead.

`key_list_raw()` is like `key_list()` but also returns the keys as raw
values. This is useful if your keys have bytes that cannot appear in R
strings, e.g. a zero byte.

### Encodings

On Windows, if required, an encoding can be specified using either an R
option (`keyring.encoding_windows`) or environment variable
(`KEYRING_ENCODING_WINDOWS`). This will be applied when both getting and
setting keys. The option takes precedence over the environment variable,
if both are set.

This is reserved primarily for compatibility with keys set with other
software, such as Python's implementation of keyring. For a list of
encodings, use [`iconvlist()`](https://rdrr.io/r/base/iconv.html),
although it should be noted that not *every* encoding can be properly
converted, even for trivial cases. For best results, use UTF-8 if you
can.

## Examples

``` r
# These examples use the default keyring, and they are interactive,
# so, we don't run them by default
if (FALSE) { # \dontrun{
key_set("R-keyring-test-service", "donaldduck")
key_get("R-keyring-test-service", "donaldduck")
if (has_keyring_support()) key_list(service = "R-keyring-test-service")
key_delete("R-keyring-test-service", "donaldduck")

## This is non-interactive, assuming that that default keyring
## is unlocked
key_set_with_value("R-keyring-test-service", "donaldduck",
                   password = "secret")
key_get("R-keyring-test-service", "donaldduck")
if (has_keyring_support()) key_list(service = "R-keyring-test-service")
key_delete("R-keyring-test-service", "donaldduck")

## This is interactive using backend_file
## Set variables to be used in keyring
kr_name <- "my_keyring"
kr_service <- "my_database"
kr_username <- "my_username"

## Create a keyring and add an entry using the variables above
kb <- keyring::backend_file$new()
## Prompt for the keyring password, used to unlock keyring
kb$keyring_create(kr_name)
## Prompt for the secret/password to be stored in the keyring
kb$set(kr_service, username=kr_username, keyring=kr_name)
# Lock the keyring
kb$keyring_lock(kr_name)

## The keyring file is stored at ~/.config/r-keyring/ on Linux

## Output the stored password
keyring::backend_file$new()$get(service = kr_service,
  user = kr_username,
  keyring = kr_name)
} # }
```
