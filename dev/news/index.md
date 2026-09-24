# Changelog

## keyring (development version)

## keyring 1.4.1

CRAN release: 2025-06-15

- keyring now compiles on FreeBSD, OpenBSD, NetSBD and DragonFlyBSD.

## keyring 1.4.0

CRAN release: 2025-05-26

- Now the “file” backend will only be selected as the default backend
  (via
  [`default_backend()`](https://keyring.r-lib.org/dev/reference/backends.md))
  if the system keyring exists for this backend. If you want to use the
  “file” backend without a system keyring, then you’ll need to select it
  explicitly. See
  [`?default_backend`](https://keyring.r-lib.org/dev/reference/backends.md).

- keyring now does not depend on the assertthat, openssl, rappdirs and
  sodium packages.

- New
  [`key_list_raw()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  method to return keys as raw vectors
  ([\#159](https://github.com/r-lib/keyring/issues/159)).

## keyring 1.3.2

CRAN release: 2023-12-10

- keyring uses safer `*printf()` format strings (Secret Service
  backend).

## keyring 1.3.1

CRAN release: 2022-10-27

- No user visible changes.

## keyring 1.3.0

CRAN release: 2021-11-29

- [`keyring_create()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  and also all backends that support multiple keyrings now allow passing
  the password when creating a new keyring
  ([\#114](https://github.com/r-lib/keyring/issues/114)).

- [`key_set()`](https://keyring.r-lib.org/dev/reference/key_get.md) can
  now use a custom prompt ([@pnacht](https://github.com/pnacht),
  [\#112](https://github.com/r-lib/keyring/issues/112)).

- keyring now handled better the ‘Cancel’ button when requesting a
  password in RStudio, and an error is thrown in this case
  ([\#106](https://github.com/r-lib/keyring/issues/106)).

## keyring 1.2.0

CRAN release: 2021-04-28

- It is now possible to specify the encoding of secrets on Windows
  ([\#88](https://github.com/r-lib/keyring/issues/88),
  [@awong234](https://github.com/awong234)).

- The `get_raw()` method of the Secret Service backend works now
  ([\#87](https://github.com/r-lib/keyring/issues/87)).

- Now the file backend is selected by default on Unix systems if Secret
  Service is not available or does not work
  ([\#95](https://github.com/r-lib/keyring/issues/95),
  [@nwstephens](https://github.com/nwstephens)).

- The file backend now works with keys that do not have a username.

- All backends use the value of the `keyring_username` option, if set,
  as the default username
  ([\#60](https://github.com/r-lib/keyring/issues/60)).

## keyring 1.1.0

CRAN release: 2018-07-16

- File based backend
  ([\#53](https://github.com/r-lib/keyring/issues/53),
  [@nbenn](https://github.com/nbenn)).

- Fix bugs in
  [`key_set()`](https://keyring.r-lib.org/dev/reference/key_get.md) on
  Linux ([\#43](https://github.com/r-lib/keyring/issues/43),
  [\#51](https://github.com/r-lib/keyring/issues/51)).

- Windows: support non-ascii characters and spaces in
  [`key_list()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  `service` and `keyring`
  ([\#48](https://github.com/r-lib/keyring/issues/48),
  [\#49](https://github.com/r-lib/keyring/issues/49),
  [@javierluraschi](https://github.com/javierluraschi)).

- Add support for listing service keys for env backend
  ([\#58](https://github.com/r-lib/keyring/issues/58),
  [@javierluraschi](https://github.com/javierluraschi)).

- keyring is now compatible with R 3.1.x and R 3.2.x.

- libsecret is now optional on Linux. If not available, keyring is built
  without the Secret Service backend
  ([\#55](https://github.com/r-lib/keyring/issues/55)).

- Fix the `get_raw()` method on Windows.

- Windows: [`get()`](https://rdrr.io/r/base/get.html) tries the UTF-16LE
  encoding if the sting has embedded zero bytes. This allows getting
  secrets that were set in Credential Manager
  ([\#56](https://github.com/r-lib/keyring/issues/56)).

- Windows: fix [`list()`](https://rdrr.io/r/base/list.html) when some
  secrets have no `:` at all (these were probably set externally)
  ([\#44](https://github.com/r-lib/keyring/issues/44)).

## keyring 1.0.0

CRAN release: 2017-09-09

First public release.
