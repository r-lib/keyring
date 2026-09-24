# Package index

## Common API

- [`keyring-package`](https://keyring.r-lib.org/dev/reference/keyring-package.md)
  [`keyring`](https://keyring.r-lib.org/dev/reference/keyring-package.md)
  : keyring: Access the System Credential Store from R
- [`key_get()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_get_raw()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_set()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_set_with_value()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_set_with_raw_value()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_delete()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_list()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  [`key_list_raw()`](https://keyring.r-lib.org/dev/reference/key_get.md)
  : Operations on keys
- [`has_keyring_support()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_create()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_list()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_delete()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_lock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_unlock()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  [`keyring_is_locked()`](https://keyring.r-lib.org/dev/reference/has_keyring_support.md)
  : Operations on keyrings

## Backends

- [`default_backend()`](https://keyring.r-lib.org/dev/reference/backends.md)
  : Select the default backend and default keyring
- [`backend_wincred`](https://keyring.r-lib.org/dev/reference/backend_wincred.md)
  : Windows Credential Store keyring backend
- [`backend_macos`](https://keyring.r-lib.org/dev/reference/backend_macos.md)
  : macOS Keychain keyring backend
- [`backend_secret_service`](https://keyring.r-lib.org/dev/reference/backend_secret_service.md)
  : Linux Secret Service keyring backend
- [`backend_file`](https://keyring.r-lib.org/dev/reference/backend_file.md)
  : Encrypted file keyring backend
- [`backend_env`](https://keyring.r-lib.org/dev/reference/backend_env.md)
  : Environment variable keyring backend

## Implementing new backends

- [`backend`](https://keyring.r-lib.org/dev/reference/backend.md) :
  Abstract class of a minimal keyring backend
- [`backend_keyrings`](https://keyring.r-lib.org/dev/reference/backend_keyrings.md)
  : Abstract class of a backend that supports multiple keyrings
