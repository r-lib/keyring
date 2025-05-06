
# keyring

<!-- badges: start -->

[![R-CMD-check](https://github.com/r-lib/keyring/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/r-lib/keyring/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/r-lib/keyring/graph/badge.svg)](https://app.codecov.io/gh/r-lib/keyring)
[![](https://www.r-pkg.org/badges/version/keyring)](https://www.r-pkg.org/pkg/keyring)
[![CRAN RStudio mirror
downloads](https://cranlogs.r-pkg.org/badges/keyring)](https://www.r-pkg.org/pkg/keyring)
<!-- badges: end -->

keyring provides a way to securely manage secrets using your operating
system’s credential store. Once a secret is defined, it persists in a
“keyring” across multiple R sessions. keyring is an alternative to using
environment variables that’s a bit more secure because your secret is
never stored in plain text, meaning that you can for instance never
accidentally upload it to GitHub. For more security, you can also store
secrets in a custom keyring that always requires a password to unlock.

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

We recommend using pak to install keyring as it will ensure that Linux
system requirements are automatically installed (for instance Ubuntu
requires `libsecret-1-dev` and `libssl-dev`).

To install the development version from GitHub, use:

``` r
pak::pak("r-lib/keyring")
```

## Usage

The simplest usage only requires `key_set()` and `key_get()`:

``` r
# Interactively save a secret. This avoids typing the value of the secret
# into the console as this could be recorded in your `.Rhistory`
key_set("secret-name")

# Later retrieve that secret
key_get("secret-name")
```

Each secret is associated with a keyring. By default, keyring will use
the OS keyring (see `default_backend()` for details), which is
automatically unlocked when you log into your computer account. That
means while the secret is stored securely, it can be accessed by other
processes.

If you want greater security you can create a custom keyring that you
manually lock and unlock. That will require you to enter a custom
password every time you want to access your secret.

``` r
keyring_create("mypackage")
key_set("secret-name", keyring = "mypackage")
key_get("secret-name", keyring = "mypackage")
```

Accessing the key unlocks the keyring, so if you’re being really
careful, you might want to lock it after you’ve retrieved the value with
`keyring_lock()`.

### GitHub

When you use keyring on GitHub, it will fall back to the environment
variable backend. That means if you want to use `key_get("mysecret")`
you need to do two things:

- Add a [new action
  secret](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-a-repository)
  to your repository.

- Make the secret available in your workflow `.yml`, for instance

  ``` yaml
      env:
        GITHUB_PAT: ${{ secrets.GITHUB_TOKEN }}
        R_KEEP_PKG_SOURCE: yes
        MY_SECRET: ${{ secrets.my_secret }}
  ```

The envvar backend doesn’t support custom keyrings, so if you’re using
one locally you’ll need to use the default keyring on GitHub.

## Development documentation

Please see our [writeup of some `keyring`
internals](https://github.com/r-lib/keyring/blob/main/inst/development-notes.md),
and as always, use the source code.
