context("Testing encoding retrieval function")

test_that("No option/env var set returns auto", {
  skip_if_not_win()
  skip_on_cran()
  encoding <- get_encoding_opt()
  expect_equal(encoding, "auto")
})

test_that("Option encoding set and env unset returns option encoding", {
  skip_if_not_win()
  skip_on_cran()
  options(keyring.encoding.windows = "utf-16le")
  encoding <- get_encoding_opt()
  expect_equal(encoding, "utf-16le")
  options(keyring.encoding.windows = NULL)
})

test_that("Option encoding unset and env set returns env encoding", {
  skip_if_not_win()
  skip_on_cran()
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-8")
  encoding <- get_encoding_opt()
  expect_equal(encoding, "utf-8")
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})

test_that("Option encoding set and env var set and EQUAL returns expected value", {
  skip_if_not_win()
  skip_on_cran()
  options(keyring.encoding.windows = "utf-16le")
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-16le")
  encoding <- get_encoding_opt()
  expect_equal(encoding, "utf-16le")
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})

test_that("Invalid encoding (not in iconvlist) returns error", {
  skip_if_not_win()
  skip_on_cran()
  options(keyring.encoding.windows = "Omicron Persei 8")
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "Omicron Persei 8")
  expect_error(get_encoding_opt())
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})

test_that("iconv suggestion works as expected", {
  skip_if_not_win()
  skip_on_cran()
  options(keyring.encoding.windows = "utf-16lp")
  expect_message(
    object = expect_error(get_encoding_opt()),
    regexp = "Encoding not found in iconvlist(). Did you mean UTF-16LE?",
    fixed = TRUE
  )
  options(keyring.encoding.windows = NULL)
})

test_that("Having two different encodings set between opt and env return error", {
  skip_if_not_win()
  skip_on_cran()
  options(keyring.encoding.windows = "x_Chinese-Eten")
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "latin9")
  expect_error(get_encoding_opt())
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})

test_that("Set key with UTF-16LE encoding", {
  skip_if_not_win()
  skip_on_cran()
  SERVICE <- random_service()
  USER <- random_username()
  PASS <- random_password()
  # Now, set a key with UTF-16LE encoding using new options
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-16le")
  keyring::key_set_with_value(service = SERVICE, username = USER, password = PASS)
  # Get the password
  expect_equal(keyring::key_get(service = SERVICE, username = USER), PASS)
  # Show that it is UTF-16LE
  raw_password <- keyring:::b_wincred_i_get(target = paste0(":", SERVICE, ":", USER))
  expect_equal(iconv(list(raw_password), from = "UTF-16LE", to = ""), PASS)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
  key_delete(service = SERVICE, username = USER)
})

test_that("Set key with UTF-16LE encoding plus a keyring", {
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-16le")
  keyring <- random_keyring()
  kb <- backend_wincred$new(keyring = keyring)
  kb$.__enclos_env__$private$keyring_create_direct(keyring, "secret123!")
  expect_true(keyring %in% kb$keyring_list()$keyring)

  list <- kb$list()
  expect_equal(nrow(list), 0)

  service <- "testService"
  username <- "testUser"
  password <- random_password()

  expect_silent(
    kb$set_with_value(service, username, password)
  )

  expect_equal(kb$get(service, username), password)
  expect_silent(kb$delete(service, username))
  expect_silent(kb$keyring_delete(keyring = keyring))
  expect_false(keyring %in% kb$keyring_list()$keyring)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})
