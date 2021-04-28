
# keyring

> Access the System Credential Store from R

<!-- badges: start -->

[![R build
status](https://github.com/r-lib/keyring/workflows/R-CMD-check/badge.svg)](https://github.com/r-lib/keyring/actions)
[![](https://www.r-pkg.org/badges/version/keyring)](https://www.r-pkg.org/pkg/keyring)
[![CRAN RStudio mirror
downloads](https://cranlogs.r-pkg.org/badges/keyring)](https://www.r-pkg.org/pkg/keyring)
[![Coverage
Status](https://img.shields.io/codecov/c/github/r-lib/keyring/master.svg)](https://codecov.io/github/r-lib/keyring?branch=master)
<!-- badges: end -->

Platform independent API to access the operating systems credential
store. Currently supports:

  - Keychain on macOS (`backend_macos`),
  - Credential Store on Windows (`backend_wincred`),
  - the Secret Service API on Linux (`backend_secret_service`),
  - encrypted files (`backend_file`), and
  - environment variables (`backend_env`).

The last two are available on all platforms. Additional storage backends
can be added easily.

## Installation

### Linux

For the Secret Service backend install the `libsecret` library, at least
version 0.16. This is typically the best keyring for a Linux desktop.
Install these packages:

  - Debian/Ubuntu: `libsecret-1-dev`
  - Recent RedHat, Fedora and CentOS systems: `libsecret-devel`

The file backend uses the sodium package, which needs the sodium
library. This backend works best on Linux servers. Install these
packages:

  - Debian/Ubuntu: `libsodium-dev`
  - Fedora, EPEL: `libsodium-devel`

### OS X and Windows

No additional software is needed.

### R package

Install the package from CRAN:

``` r
install.packages("keyring")
```

## Usage

### Query secret keys in a keyring:

Each keyring can contain one or many secrets (keys). A key is defined by
a service name and a password. Once a key is defined, it persists in the
keyring store of the operating system. This means the keys persist
beyond the termination of and R session. Specifically, you can define a
key once, and then read the key value in completely independent R
sessions.

  - Setting a secret interactively: `key_set()`
  - Setting a secret from a script, i.e. non-interactively:
    `key_set_with_value()`
  - Reading a secret: `key_get()`
  - Listing secrets: `key_list()`
  - Deleting a secret: `key_delete()`

### Configure an OS-specific backend:

  - The default is operating system specific, and is described in manual
    page of `default_backend()`. In most cases you don’t have to
    configure this.
  - MacOS: `backend_macos`.
  - Linux: `backend_secret_service`, if build with `libsecret`.
  - Windows: `backend_wincred`
  - Or store the secrets in encrypted files: `backend_file`.

Should you need to change the default backend, set the
`R_KEYRING_BACKEND` environment variable or the `keyring_backend` R
option to the backend’s name (e.g. `env`, `file`, etc.).

### Manage keyrings:

A keyring is a collection of keys that can be treated as a unit. A
keyring typically has a name and a password to unlock it. See
`keyring_create()`, `keyring_delete()`, `keyring_list()`,
`keyring_lock()`, `keyring_unlock()`, `keyring_is_locked()`.

Note that all platforms have a default keyring, and `key_get()`, etc.
will use that automatically. The default keyring is also convenient,
because usually the OS unlocks it automatically when you log in, so
secrets are available immediately. But note that the file backend does
not currently unlock its default keyring.

You only need to explicitly deal with keyrings and the `keyring_*`
functions if you want to use a different keyring.

## Development documentation

Please see our [writeup of some `keyring`
internals](https://github.com/r-lib/keyring/blob/master/inst/development-notes.md),
and as always, use the source code.

## License

MIT © RStudio
