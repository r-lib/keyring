# keyring: Access the System Credential Store from R

Platform independent 'API' to access the operating system's credential
store. Currently supports: 'Keychain' on 'macOS', Credential Store on
'Windows', the Secret Service 'API' on 'Linux', and simple, platform
independent stores implemented with environment variables or encrypted
files. Additional storage back-ends can be added easily.

Platform independent API to many system credential store
implementations. Currently supported:

- Keychain on macOS,

- Credential Store on Windows,

- the Secret Service API on Linux, and

- environment variables on other platforms.

## Configuring an OS-specific backend

- The default is operating system specific, and is described in
  [`default_backend()`](https://keyring.r-lib.org/dev/reference/backends.md).
  In most cases you don't have to configure this.

- MacOS:
  [backend_macos](https://keyring.r-lib.org/dev/reference/backend_macos.md)

- Linux:
  [backend_secret_service](https://keyring.r-lib.org/dev/reference/backend_secret_service.md)

- Windows:
  [backend_wincred](https://keyring.r-lib.org/dev/reference/backend_wincred.md)

- Or store the secrets in environment variables on other operating
  systems:
  [backend_env](https://keyring.r-lib.org/dev/reference/backend_env.md)

## Query secret keys in a keyring

Each keyring can contain one or many secrets (keys). A key is defined by
a service name and a password. Once a key is defined, it persists in the
keyring store of the operating system. This means the keys persist
beyond the termination of and R session. Specifically, you can define a
key once, and then read the key value in completely independent R
sessions.

- Setting a secret interactively:
  [`key_set()`](https://keyring.r-lib.org/dev/reference/key_get.md).

- Setting a secret from a script, i.e. non-interactively:
  [`key_set_with_value()`](https://keyring.r-lib.org/dev/reference/key_get.md).

- Reading a secret:
  [`key_get()`](https://keyring.r-lib.org/dev/reference/key_get.md),
  [`key_get_raw()`](https://keyring.r-lib.org/dev/reference/key_get.md).

- Listing secrets:
  [`key_list()`](https://keyring.r-lib.org/dev/reference/key_get.md),
  [`key_list_raw()`](https://keyring.r-lib.org/dev/reference/key_get.md).

- Deleting a secret:
  [`key_delete()`](https://keyring.r-lib.org/dev/reference/key_get.md).

## Managing keyrings

A keyring is a collection of keys that can be treated as a unit. A
keyring typically has a name and a password to unlock it.

- [`keyring_create()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)

- [`keyring_delete()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)

- [`keyring_list()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)

- [`keyring_lock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)

- [`keyring_unlock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)

Note that all platforms have a default keyring, and
[`key_get()`](https://keyring.r-lib.org/dev/reference/key_get.md), etc.
will use that automatically. The default keyring is also convenient,
because the OS unlocks it automatically when you log in, so secrets are
available immediately.

You only need to explicitly deal with keyrings and the `keyring_*`
functions if you want to use a different keyring.

## See also

Useful links:

- <https://keyring.r-lib.org/>

- <https://github.com/r-lib/keyring>

- Report bugs at <https://github.com/r-lib/keyring/issues>

Useful links:

- <https://keyring.r-lib.org/>

- <https://github.com/r-lib/keyring>

- Report bugs at <https://github.com/r-lib/keyring/issues>

## Author

**Maintainer**: Gábor Csárdi <csardi.gabor@gmail.com>

Other contributors:

- Alec Wong \[contributor\]

- Posit Software, PBC ([ROR](https://ror.org/03wc8by49)) \[copyright
  holder, funder\]
