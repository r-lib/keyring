
context("Windows credential store")

test_that("low level API", {
  skip_if_not_win()
  skip_on_cran()

  keyring <- random_keyring()
  service <- random_service()
  username <- random_username()
  password <- random_password()

  target <- b_wincred_target(keyring, service, username)

  expect_false(b_wincred_i_exists(target))
  expect_silent(b_wincred_i_set(target, charToRaw(password),
                                username, session = TRUE))
  expect_true(b_wincred_i_exists(target))
  expect_equal(rawToChar(b_wincred_i_get(target)), password)
  expect_true(target %in% b_wincred_i_enumerate("*"))

  expect_silent(b_wincred_i_delete(target))
  expect_false(b_wincred_i_exists(target))
  expect_false(target %in% b_wincred_i_enumerate("*"))
})

test_that("creating keychains", {
  skip_if_not_win()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_wincred$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")
  expect_true(keyring %in% kb$keyring_list()$keyring)

  list <- kb$list()
  expect_equal(nrow(list), 0)

  service <- random_service()
  username <- random_username()
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)

  expect_silent(kb$delete(service, username))

  expect_silent(kb$keyring_delete(keyring = keyring))

  expect_false(keyring %in% kb$keyring_list()$keyring)
})

test_that("lock/unlock keyrings", {
  skip_if_not_win()
  skip_on_cran()

  keyring <- random_keyring()
  kb <- backend_wincred$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")

  ## It is unlocked by default
  expect_false(kb$keyring_is_locked())
  list <- kb$keyring_list()
  expect_true(keyring %in% list$keyring)
  expect_false(list$locked[match(keyring, list$keyring)])

  ## Lock it
  kb$keyring_lock()
  expect_true(kb$keyring_is_locked())
  list <- keyring_list()
  expect_true(list$locked[match(keyring, list$keyring)])

  ## Unlock it
  kb$keyring_unlock(password = "secret123!")
  expect_false(kb$keyring_is_locked())
  list <- kb$keyring_list()
  expect_false(list$locked[match(keyring, list$keyring)])

  expect_silent(kb$keyring_delete(keyring = keyring))
})

test_that(": in keyring, service and usernames", {
  skip_if_not_win()
  skip_on_cran()

  keyring <- paste0("foo:", random_keyring())
  service <- paste0("bar:", random_service())
  username <- paste0("foobar:", random_username())
  password <- random_password()

  target <- b_wincred_target(keyring, service, username)

  expect_false(b_wincred_i_exists(target))
  expect_silent(b_wincred_i_set(target, charToRaw(password),
                                username, session = TRUE))
  expect_true(b_wincred_i_exists(target))
  expect_equal(rawToChar(b_wincred_i_get(target)), password)
  expect_true(target %in% b_wincred_i_enumerate("*"))

  expect_silent(b_wincred_i_delete(target))
  expect_false(b_wincred_i_exists(target))
  expect_false(target %in% b_wincred_i_enumerate("*"))
})
