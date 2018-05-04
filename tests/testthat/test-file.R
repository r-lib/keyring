
context("file-based keyring")

test_that("specify keyring explicitly", {

  service <- random_service()
  username <- random_username()
  password <- random_password()
  keyring <- random_keyring()

  kb <- backend_file$new(keyring = keyring)

  expect_true(kb$keyring_is_locked())
  expect_silent(kb$keyring_unlock(password = random_password()))
  expect_false(kb$keyring_is_locked())

  expect_silent(kb$set_with_value(service, username, password))

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$keyring_delete())
})

test_that("key consistency check", {

  service <- random_service()
  username <- random_username()
  password <- random_password()
  keyring <- random_keyring()
  keyring_pwd_1 <- random_password()
  keyring_pwd_2 <- random_password()

  kb <- backend_file$new(keyring = keyring)

  expect_silent(kb$keyring_unlock(password = keyring_pwd_1))
  expect_silent(kb$set_with_value(service, username, password))

  expect_silent(kb$keyring_unlock(password = keyring_pwd_2))
  expect_silent(kb$keyring_lock())

  expect_error(kb$keyring_unlock(password = keyring_pwd_2),
               "failed to unlock keyring")

  kb$.__enclos_env__$private$key_set(keyring_pwd_2)
  expect_true(kb$keyring_is_locked())

  expect_silent(kb$keyring_unlock(password = keyring_pwd_1))
  expect_silent(kb$keyring_delete())
})
