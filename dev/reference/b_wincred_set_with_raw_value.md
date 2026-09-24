# Set a key on a Wincred keyring

Set a key on a Wincred keyring

## Usage

``` r
b_wincred_set_with_raw_value(
  self,
  private,
  service,
  username,
  password,
  keyring
)
```

## Arguments

- service:

  Service name. Must not be empty.

- username:

  Username. Might be empty.

- password:

  The key text to store.

  1.  Check if we are using the default keyring.

  2.  If yes, then just store the key and we are done.

  3.  Otherwise check if keyring exists.

  4.  If not, error and finish.

  5.  If yes, check if it is locked.

  6.  If yes, unlock it.

  7.  Encrypt the key with the AES key, and store it.

  If required, an encoding can be specified using either an R option
  (`keyring.encoding_windows`) or environment variable
  (`KEYRING_ENCODING_WINDOWS`). To set, use one of:

  `options(keyring.encoding_windows = 'encoding-type')`
  `Sys.setenv("KEYRING_ENCODING_WINDOWS" = 'encoding-type')`

  For a list of valid encodings, use
  [`iconvlist()`](https://rdrr.io/r/base/iconv.html)
