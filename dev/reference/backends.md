# Select the default backend and default keyring

The default backend is selected

1.  based on the `keyring_backend` option. See
    [`base::options()`](https://rdrr.io/r/base/options.html). This can
    be set to a character string, and then the *backend\_*`string` class
    is used to create the default backend.

2.  If this is not set, then the `R_KEYRING_BACKEND` environment
    variable is checked.

3.  If this is not set, either, then the backend is selected
    automatically, based on the OS:

    1.  On Windows, the Windows Credential Store (`"wincred"`) is used.

    2.  On macOS, Keychain services are selected (`"macos"`).

    3.  Linux uses the Secret Service API (`"secret_service"`), and it
        also checks that the service is available. It is typically only
        available on systems with a GUI.

    4.  If the file backend (`"file"`) is available, it is selected.

    5.  On other operating systems, secrets are stored in environment
        variables (`"env"`).

## Usage

``` r
default_backend(keyring = NULL)
```

## Arguments

- keyring:

  Character string, the name of the keyring to use, or `NULL` for the
  default keyring.

## Value

The backend object itself.

## Details

Most backends support multiple keyrings. For these the keyring is
selected from:

1.  the supplied `keyring` argument (if not `NULL`), or

2.  the `keyring_keyring` option.

    - You can change this by using
      `options(keyring_keyring = "NEWVALUE")`

3.  If this is not set, the `R_KEYRING_KEYRING` environment variable.

    - Change this value with
      `Sys.setenv(R_KEYRING_KEYRING = "NEWVALUE")`, either in your
      script or in your `.Renviron` file. See
      [base::Startup](https://rdrr.io/r/base/Startup.html) for
      information about using `.Renviron`

4.  Finally, if neither of these are set, the OS default keyring is
    used.

    - Usually the keyring is automatically unlocked when the user logs
      in.

## See also

[backend_env](https://keyring.r-lib.org/dev/reference/backend_env.md),
[backend_file](https://keyring.r-lib.org/dev/reference/backend_file.md),
[backend_macos](https://keyring.r-lib.org/dev/reference/backend_macos.md),
[backend_secret_service](https://keyring.r-lib.org/dev/reference/backend_secret_service.md),
[backend_wincred](https://keyring.r-lib.org/dev/reference/backend_wincred.md)
