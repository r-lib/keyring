# locking the keyring file

    Code
      kb$set_with_value(service_1, username, password)
    Condition
      Error in `with_lock()`:
      ! Cannot lock keyring file

# keyring does not exist

    Code
      kb$list()
    Condition
      Error in `b__file_keyring_autocreate()`:
      ! The 'system' keyring does not exists, create it first!
    Code
      kb$keyring_is_locked()
    Condition
      Error in `b__file_keyring_autocreate()`:
      ! The 'system' keyring does not exists, create it first!
    Code
      kb$keyring_unlock()
    Condition
      Error in `b_file_keyring_unlock()`:
      ! Keyring `` does not exist
    Code
      kb$set_with_value("service", "user", "pass")
    Condition
      Error in `b__file_keyring_autocreate()`:
      ! The 'system' keyring does not exists, create it first!

