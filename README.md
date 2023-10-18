
# keyring

<!-- badges: start -->

[![R-CMD-check](https://github.com/r-lib/keyring/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/r-lib/keyring/actions/workflows/R-CMD-check.yaml)
[![](https://www.r-pkg.org/badges/version/keyring)](https://www.r-pkg.org/pkg/keyring)
[![CRAN RStudio mirror
downloads](https://cranlogs.r-pkg.org/badges/keyring)](https://www.r-pkg.org/pkg/keyring)
[![Codecov test
coverage](https://codecov.io/gh/r-lib/keyring/branch/main/graph/badge.svg)](https://app.codecov.io/gh/r-lib/keyring?branch=main)

<!-- badges: end -->

keyring provides a way to securely manage secrets using your operating
system’s credential store. Once a secret is defined, it persists in the
keyring across multiple R sessions. keyring is an alternative to using
env vars that’s a bit more secure because your secret is never stored in
plain text, meaning that you can (e.g.) never accidentally upload it to
GitHub.

keyring currently supports:

- The macOS Keychain (`backend_macos`).
- The Windows Credential Store (`backend_wincred`).
- The Linux Secret Service API (`backend_secret_service`).

It also provides two backends that are available on all platforms:

- Encrypted files (`backend_file`)
- Environment variables (`backend_env`).

## Installation

Install the package from CRAN:

``` r
# install.packages("pak")
pak::pak("keyring")
```

We recommend using pak to install keyring as it will ensure that all
Linux system requirements (e.g. `libsecret-devel`, `openssl-devel`) are
automatically installed.

## Usage

The simplest usage only requires `key_set()` and `key_get()`:

``` r
# Interactively save a secret. This avoids typing the value of the secret
# into the console as this will be recorded in your `.Rhistory`
key_set("secret-name")

# Later retrieve that secret
key_get("secret-name")
```

Each secret is associated with a keyring. By default, keyring will use
the OS keyring (see `default_backend()` for details), which is
automatically unlocked you log in. That means while the secret is stored
securely, it can be accessed by other processes.

If you want greater security you can create a custom keyring that you
manually lock and unlock. That will require you to enter your system
password every time you want to access your secret.

``` r
keyring_create("mypackage")
key_set("MY_SECRET", keyring = "mypackage")
key_get("MY_SECRET", keyring = "mypackage")
```

Note that accessing the key unlocks the keyring, so if you’re being
really careful, make sure to lock it again afterwards.

``` r
keyring_lock("httr")
```

## Development documentation

Please see our [writeup of some `keyring`
internals](https://github.com/r-lib/keyring/blob/main/inst/development-notes.md),
and as always, use the source code.
