
context("file-based keyring")

test_that("specify keyring explicitly", {

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE))
  withr::local_options(list(keyring_file_dir = tmp))

  service_1 <- random_service()
  username <- random_username()
  password <- random_password()
  password2 <- random_password()
  keyring <- random_keyring()

  kb <- backend_file$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")

  expect_false(kb$keyring_is_locked(keyring))
  kb$keyring_lock(keyring)
  expect_true(kb$keyring_is_locked(keyring))
  expect_silent(kb$keyring_unlock(keyring,  password = "secret123!"))
  expect_false(kb$keyring_is_locked(keyring))

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
  keyring <- random_keyring()
  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  withr::local_options(list(keyring_file_dir = tmp))

  keyring_pwd_1 <- random_password()
  keyring_pwd_2 <- random_password()

  kb <- backend_file$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, keyring_pwd_1)

  expect_silent(kb$keyring_unlock(password = keyring_pwd_1))
  expect_silent(kb$set_with_value(random_service(), username, password))

  expect_error(kb$keyring_unlock(password = keyring_pwd_2),
               "cannot unlock keyring")

  expect_silent(kb$keyring_lock())
  expect_error(kb$keyring_unlock(password = keyring_pwd_2),
               "cannot unlock keyring")

  kb$.__enclos_env__$private$set_keyring_pass(keyring_pwd_2)
  expect_true(kb$keyring_is_locked())
  kb$.__enclos_env__$private$unset_keyring_pass()

  with_mock(`keyring:::get_pass` = mockery::mock(keyring_pwd_1), {
    expect_silent(kb$set_with_value(random_service(), username, password))
  })

  expect_silent(kb$keyring_delete())
})

test_that("use non-default keyring", {

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  withr::local_options(list(keyring_file_dir = tmp))

  service <- random_service()
  username <- random_username()
  password <- random_password()
  default_keyring <- random_keyring()
  keyring <- random_keyring()
  default_keyring_pwd <- random_password()
  keyring_pwd <- random_password()

  kb <- backend_file$new(keyring = default_keyring)
  kb$.__enclos_env__$private$keyring_create_direct(password = default_keyring_pwd)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, keyring_pwd)

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

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  withr::local_options(list(keyring_file_dir = tmp))

  service <- random_service()
  username <- random_username()

  keyring <- random_keyring()
  keyring_pwd <- random_password()

  kb <- backend_file$new(keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, keyring_pwd)
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

test_that("keys updated from another session", {

  skip_on_cran()

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  withr::local_options(list(keyring_file_dir = tmp))

  service_1 <- random_service()
  username <- random_username()
  username2 <- random_username()
  password <- random_password()
  password2 <- random_password()

  keyring <- random_keyring()
  kb <- backend_file$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "foobar")

  kb$keyring_unlock(password = "foobar")
  kb$set_with_value(service_1, username, password)

  ret <- callr::r(function(s, u, p, k, dir) {
    options(keyring_file_dir = dir)
    kb <- keyring::backend_file$new(keyring = k)
    kb$keyring_unlock(password = "foobar")
    kb$set_with_value(s, u, p)
    kb$get(s, u) },
    args = list(s = service_1, u = username2, p = password2, k = keyring,
                dir = tmp))

  expect_equal(ret, password2)

  expect_equal(kb$get(service_1, username), password)
  expect_equal(kb$get(service_1, username2), password2)
  expect_equal(kb$get(service_1, username), password)
})

test_that("locking the keyring file", {

  skip_on_cran()

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  withr::local_options(list(keyring_file_dir = tmp))

  service_1 <- random_service()
  username <- random_username()
  password <- random_password()

  keyring <- random_keyring()

  kb <- backend_file$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(password = "foobar")

  lockfile <- paste0(kb$.__enclos_env__$private$keyring_file(), ".lck")

  rb <- callr::r_bg(function(lf) {
    l <- filelock::lock(lf)
    cat("done\n");
    Sys.sleep(3) },
    args = list(lf = lockfile),
    stdout = "|"
  )
  on.exit(rb$kill(), add = TRUE)
  rb$poll_io(3000)

  withr::with_options(
    list(keyring_file_lock_timeout = 100),
    expect_error(
      kb$set_with_value(service_1, username, password),
      "Cannot lock keyring file")
  )
})

test_that("keyring does not exist", {

  dir.create(tmp <- tempfile())
  on.exit(unlink(tmp, recursive = TRUE))
  withr::local_options(list(keyring_file_dir = tmp))

  kb <- backend_file$new()

  expect_error(kb$list())
  expect_error(kb$keyring_is_locked())
  expect_error(kb$keyring_unlock())
  expect_error(kb$set_with_value("service", "user", "pass"))
})
