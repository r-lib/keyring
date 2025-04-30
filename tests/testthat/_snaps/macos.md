# errors

    Code
      backend_macos$new(tempfile())$list()
    Condition
      Error in `b_macos_list()`:
      ! keyring error (macOS Keychain), cannot open keychain: The specified keychain could not be found.

---

    Code
      backend_macos$new()$get(random_service(), random_username())
    Condition
      Error in `b_macos_get()`:
      ! keyring error (macOS Keychain), cannot get password: The specified item could not be found in the keychain.

---

    Code
      backend_macos$new()$delete(random_service(), random_username())
    Condition
      Error in `b_macos_delete()`:
      ! keyring error (macOS Keychain), cannot delete password: The specified item could not be found in the keychain.

---

    Code
      kb$.__enclos_env__$private$keyring_create_direct("/xxx", "secret123!")
    Condition
      Error in `b_macos_keyring_create_direct()`:
      ! keyring error (macOS Keychain), cannot create keychain: UNIX[Read-only file system]

# zero bytes in keys

    Code
      b_macos_list(NULL, list(keyring_file = function(...) NULL))
    Condition
      Warning in `b_macos_list()`:
      Some service names contain zero bytes. These are shown as NA. Use `key_list_raw()` to see them.
    Output
        service username
      1     foo      bar
      2    <NA>      baz
    Code
      b_macos_list_raw(NULL, list(keyring_file = function(...) NULL))
    Output
        service username    service_raw username_raw
      1     foo      bar     66, 6f, 6f   62, 61, 72
      2    <NA>      baz 03, 02, 01, 00   62, 61, 7a

---

    Code
      b_macos_list(NULL, list(keyring_file = function(...) NULL))
    Condition
      Warning in `b_macos_list()`:
      Some service names and some user names contain zero bytes. These are shown as NA. Use `key_list_raw()` to see them.
    Output
        service username
      1     foo      bar
      2    <NA>     <NA>
    Code
      b_macos_list_raw(NULL, list(keyring_file = function(...) NULL))
    Output
        service username    service_raw       username_raw
      1     foo      bar     66, 6f, 6f         62, 61, 72
      2    <NA>     <NA> 03, 02, 01, 00 01, 02, 00, 01, 02

---

    Code
      b_macos_list(NULL, list(keyring_file = function(...) NULL))
    Condition
      Warning in `b_macos_list()`:
      Some user names contain zero bytes. These are shown as NA. Use `key_list_raw()` to see them.
    Output
        service username
      1     foo      bar
      2     baz     <NA>
    Code
      b_macos_list_raw(NULL, list(keyring_file = function(...) NULL))
    Output
        service username service_raw   username_raw
      1     foo      bar  66, 6f, 6f     62, 61, 72
      2     baz     <NA>  62, 61, 7a 03, 02, 01, 00

