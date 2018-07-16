
# 1.1.0

* File based backend (#53, @nbenn).

* Fix bugs in `key_set()` on Linux (#43, #51).

* Windows: support non-ascii characters and spaces in `key_list()`
  `service` and `keyring` (#48, #49, @javierluraschi).

* Add support for listing service keys for env backend
  (#58, @javierluraschi).

* keyring is now compatible with R 3.1.x and R 3.2.x.

* libsecret is now optional on Linux. If not available, keyring is built
  without the Secret Service backend (#55).

* Fix the `get_raw()` method on Windows.

* Windows: `get()` tries the UTF-16LE encoding if the sting has embedded
  zero bytes. This allows getting secrets that were
  set in Credential Manager (#56).

* Windows: fix `list()` when some secrets have no `:` at all
  (these were probably set externally) (#44).

# 1.0.0

First public release.
