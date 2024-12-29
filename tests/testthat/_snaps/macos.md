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

