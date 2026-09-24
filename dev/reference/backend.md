# Abstract class of a minimal keyring backend

To implement a new keyring backend, you need to inherit from this class
and then redefine the `get`, `set`, `set_with_value` and `delete`
methods. Implementing the `list` method is optional. Additional methods
can be defined as well.

## Details

These are the semantics of the various methods:

    get(service, username = NULL, keyring = NULL)
    get_raw(service, username = NULL, keyring = NULL)
    set(service, username = NULL, keyring = NULL, prompt = "Password: ")
    set_with_value(service, username = NULL, password = NULL,
                   keyring = NULL)
    set_with_raw_value(service, username = NULL, password = NULL,
                   keyring = NULL)
    delete(service, username = NULL, keyring = NULL)
    list(service = NULL, keyring = NULL)
    list_raw(service = NULL, keyring = NULL)

What these functions do:

- [`get()`](https://rdrr.io/r/base/get.html) queries the secret in a
  keyring item.

- `get_raw()` is similar to [`get()`](https://rdrr.io/r/base/get.html),
  but returns the result as a raw vector.

- `set()` sets the secret in a keyring item. The secret itself is read
  in interactively from the keyboard.

- `set_with_value()` sets the secret in a keyring item to the specified
  value.

- `set_with_raw_value()` sets the secret in keyring item to the byte
  sequence of a raw vector.

- `delete()` remotes a keyring item.

- [`list()`](https://rdrr.io/r/base/list.html) lists keyring items.

- `list_raw()` lists keyring items, also as raw vectors.

The arguments:

- `service` String, the name of a service. This is used to find the
  secret later.

- `username` String, the username associated with a secret. It can be
  `NULL`, if no username belongs to the secret. It uses the value of the
  `keyring_username`, if set.

- `keyring` String, the name of the keyring to work with. This only
  makes sense if the platform supports multiple keyrings. `NULL` selects
  the default (and maybe only) keyring.

- `password` The value of the secret, typically a password, or other
  credential.

- `prompt` String, the text to be displayed above the textbox.

## See also

Other keyring backend base classes:
[`backend_keyrings`](https://keyring.r-lib.org/dev/reference/backend_keyrings.md)
