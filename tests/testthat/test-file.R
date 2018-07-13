
context("file-based keyring")

test_that("specify keyring explicitly", {

  service_1 <- random_service()
  username <- random_username()
  password <- random_password()
  password2 <- random_password()
  keyring <- file.path(new_empty_dir(), random_keyring())

  kb <- backend_file$new(keyring = keyring)

  expect_true(kb$keyring_is_locked())
  expect_silent(kb$keyring_unlock(password = random_password()))
  expect_false(kb$keyring_is_locked())

  ## Missing
  expect_error(kb$get(service_1, username), "could not be found")

  expect_silent(kb$set_with_value(service_1, username, password))
  expect_equal(kb$get(service_1, username), password)

  ## Missing
  expect_error(kb$get(service_1, "foobar"), "could not be found")

  ## Overwrite
  expect_silent(kb$set_with_value(service_1, username, password2))
  expect_equal(kb$get(service_1, username), password2)

  expect_silent(kb$set_with_value(random_service(), username, password))

  long_password <- random_string(500L)
  service_2 <- random_service()

  expect_silent(kb$set_with_value(service_2, username, long_password))
  expect_equal(kb$get(service_2, username), long_password)

  ## Delete
  expect_silent(kb$delete(service_1, username))
  expect_error(kb$get(service_1, username), "could not be found")

  ## Delete non-existent is  silent
  expect_silent(kb$delete(service_1, username))

  expect_silent(kb$keyring_delete())
})

test_that("key consistency check", {

  username <- random_username()
  password <- random_password()
  keyring <- file.path(new_empty_dir(), random_keyring())
  keyring_pwd_1 <- random_password()
  keyring_pwd_2 <- random_password()

  kb <- backend_file$new(keyring = keyring)

  expect_silent(kb$keyring_unlock(password = keyring_pwd_1))
  expect_silent(kb$set_with_value(random_service(), username, password))

  expect_error(kb$keyring_unlock(password = keyring_pwd_2),
               "cannot unlock keyring")

  expect_silent(kb$keyring_lock())
  expect_error(kb$keyring_unlock(password = keyring_pwd_2),
               "cannot unlock keyring")

  kb$.__enclos_env__$private$key_set(keyring_pwd_2)
  expect_true(kb$keyring_is_locked())
  kb$.__enclos_env__$private$key_unset()

  with_mock(`keyring:::get_pass` = mockery::mock(keyring_pwd_1), {
    expect_silent(kb$set_with_value(random_service(), username, password))
  })

  expect_silent(kb$keyring_delete())
})

test_that("use non-default keyring", {

  service <- random_service()
  username <- random_username()
  password <- random_password()
  default_keyring <- file.path(new_empty_dir(), random_keyring())
  keyring <- file.path(new_empty_dir(), random_keyring())
  default_keyring_pwd <- random_password()
  keyring_pwd <- random_password()

  kb <- backend_file$new(keyring = default_keyring)
  expect_silent(kb$keyring_unlock(password = default_keyring_pwd))
  expect_false(kb$keyring_is_locked())

  expect_silent(kb$keyring_unlock(keyring, keyring_pwd))
  expect_false(kb$keyring_is_locked(keyring))
  expect_false(kb$keyring_is_locked())

  expect_silent(kb$set_with_value(service, username, password, keyring))
  expect_equal(kb$get(service, username, keyring), password)

  expect_silent(
    all_items <- kb$list(keyring = keyring)
  )

  expect_is(all_items, "data.frame")
  expect_equal(nrow(all_items), 1L)
  expect_named(all_items, c("service", "username"))

  expect_silent(kb$keyring_delete())
  expect_silent(kb$keyring_delete(keyring))
})

test_that("list keyring items", {

  service <- random_service()
  username <- random_username()

  keyring <- file.path(new_empty_dir(), random_keyring())
  keyring_pwd <- random_password()

  kb <- backend_file$new(keyring)
  expect_silent(kb$keyring_unlock(password = keyring_pwd))

  expect_silent(kb$set_with_value(random_service(),
                                  random_username(),
                                  random_password()))
  expect_silent(kb$set_with_value(service, random_username(),
                                  random_password()))
  expect_silent(kb$set_with_value(service, random_username(),
                                  random_password()))

  expect_silent(
    all_items <- kb$list()
  )

  expect_is(all_items, "data.frame")
  expect_equal(nrow(all_items), 3L)
  expect_named(all_items, c("service", "username"))

  expect_silent(
    some_items <- kb$list(service)
  )

  expect_is(some_items, "data.frame")
  expect_equal(nrow(some_items), 2L)
  expect_named(some_items, c("service", "username"))
  invisible(sapply(some_items[["service"]], expect_identical, service))

  expect_silent(kb$keyring_delete(keyring))
})

test_that("helper functions work", {

  secret <- random_password()
  long_secret <- random_string(500L)
  nonce <- sodium::random(24L)
  password <- sodium::hash(charToRaw(random_password()))

  expect_identical(b_file_split_string(secret), secret)
  expect_true(
    assertthat::is.string(
      split_key <- b_file_split_string(long_secret)
    )
  )
  expect_match(split_key, "\\n")
  expect_identical(b_file_merge_string(split_key), long_secret)

  expect_identical(
    b_file_secret_decrypt(
      b_file_secret_encrypt(secret, nonce, password),
      nonce,
      password
    ),
    secret
  )

  expect_identical(
    b_file_secret_decrypt(
      b_file_secret_encrypt(long_secret, nonce, password),
      nonce,
      password
    ),
    long_secret
  )
})

test_that("multiple sessions", {
  ## TODO
})

test_that("keys updated from another session", {
  ## TODO
})

test_that("locking the keyring file", {
  ## TODO
})
