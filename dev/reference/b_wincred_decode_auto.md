# Decode a raw password obtained by b_wincred_get_raw (UTF-8 and UTF-16LE only)

It attempts to use UTF-16LE conversion if there are 0 values in the
password.

## Usage

``` r
b_wincred_decode_auto(password)
```

## Arguments

- password:

  Raw vector coming from the keyring.
