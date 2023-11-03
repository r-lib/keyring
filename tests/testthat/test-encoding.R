test_that("No option/env var set returns auto", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = NULL)
  withr::local_envvar(KEYRING_ENCODING_WINDOWS = NA_character_)
  encoding <- get_encoding_opt()
  expect_equal(encoding, "auto")
})

test_that("Option encoding set and env unset returns option encoding", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = "UTF-16LE")
  withr::local_envvar(KEYRING_ENCODING_WINDOWS = NA_character_)
  encoding <- get_encoding_opt()
  expect_equal(encoding, "UTF-16LE")
})

test_that("Option encoding unset and env set returns env encoding", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = NULL)
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = "UTF-8")
  encoding <- get_encoding_opt()
  expect_equal(encoding, "UTF-8")
})

test_that("Option encoding set and env var set and EQUAL returns expected value", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = "UTF-16LE")
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = "UTF-16LE")
  encoding <- get_encoding_opt()
  expect_equal(encoding, "UTF-16LE")
})

test_that("Invalid encoding (not in iconvlist) returns error", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = "doesnotexist")
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = "doesnotexist")
  expect_error(get_encoding_opt())
})

test_that("iconv suggestion works as expected", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = "UTF-16LP")
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = NA_character_)
  expect_error(
    get_encoding_opt(),
    "Encoding not found in iconvlist(). Did you mean UTF-16LE?",
    fixed = TRUE
  )
})

test_that("Option has precedence", {
  skip_if_not_win()
  withr::local_options(keyring.encoding_windows = iconvlist()[1])
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = iconvlist()[2])
  expect_identical(get_encoding_opt(), iconvlist()[1])
})

test_that("Set key with UTF-16LE encoding", {
  skip_if_not_win()
  skip_on_cran()
  service <- random_service()
  user <- random_username()
  pass <- random_password()
  # Now, set a key with UTF-16LE encoding using new options
  withr::local_options(keyring.encoding_windows = NULL)
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = "UTF-16LE")
  keyring::key_set_with_value(service = service, username = user, password = pass)
  # Get the password
  expect_equal(keyring::key_get(service = service, username = user), pass)
  # Show that it is UTF-16LE
  raw_password <- keyring:::b_wincred_i_get(target = paste0(":", service, ":", user))
  expect_equal(iconv(list(raw_password), from = "UTF-16LE", to = ""), pass)
  key_delete(service = service, username = user)
})

test_that("Set key with UTF-16LE encoding plus a keyring", {
  skip_if_not_win()
  skip_on_cran()
  withr::local_options(keyring.encoding_windows = NULL)
  withr::local_envvar("KEYRING_ENCODING_WINDOWS" = "UTF-16LE")
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

test_that("marked UTF-8 strings work", {
  skip_if_not_win()
  skip_on_cran()
  withr::local_options(keyring.encoding_windows = "UTF-8")

  service <- random_service()
  user <- random_username()
  pass <- "this is ok: \u00bc"

  keyring::key_set_with_value(service = service, username = user, password = pass)

  # Get the password
  expect_equal(keyring::key_get(service = service, username = user), pass)

  key_delete(service = service, username = user)
})
