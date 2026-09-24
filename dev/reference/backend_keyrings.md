# Abstract class of a backend that supports multiple keyrings

To implement a new keyring that supports multiple keyrings, you need to
inherit from this class and redefine the `get`, `set`, `set_with_value`,
`delete`, `list` methods, and also the keyring management methods:
`keyring_create`, `keyring_list`, `keyring_delete`, `keyring_lock`,
`keyring_unlock`, `keyring_is_locked`, `keyring_default` and
`keyring_set_default`.

## Details

See [backend](https://keyring.r-lib.org/dev/reference/backend.md) for
the first set of methods. This is the semantics of the keyring
management methods:

    keyring_create(keyring)
    keyring_list()
    keyring_delete(keyring = NULL)
    keyring_lock(keyring = NULL)
    keyring_unlock(keyring = NULL, password = NULL)
    keyring_is_locked(keyring = NULL)
    keyring_default()
    keyring_set_default(keyring = NULL)

- [`keyring_create()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  creates a new keyring.

- [`keyring_list()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  lists all keyrings.

- [`keyring_delete()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  deletes a keyring. It is a good idea to protect the default keyring,
  and/or a non-empty keyring with a password or a confirmation dialog.

- [`keyring_lock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  locks a keyring.

- [`keyring_unlock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  unlocks a keyring.

- [`keyring_is_locked()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  checks whether a keyring is locked.

- `keyring_default()` returns the default keyring.

- `keyring_set_default()` sets the default keyring.

Arguments:

- `keyring` is the name of the keyring to use or create. For some
  methods in can be `NULL` to select the default keyring.

- `password` is the password of the keyring.

## See also

Other keyring backend base classes:
[`backend`](https://keyring.r-lib.org/dev/reference/backend.md)
