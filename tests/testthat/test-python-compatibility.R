# Setup ------------------------------------------------------------------------

library(reticulate)
library(keyring)

context("Testing encoding retrieval function")

test_that("No option/env var set returns auto", {
  encoding = get_encoding_opt()
  expect_equal(encoding, 'auto')
})

test_that("Option encoding set and env unset returns option encoding", {
  options(keyring.encoding.windows = 'utf-16le')
  encoding = get_encoding_opt()
  expect_equal(encoding, 'utf-16le')
  options(keyring.encoding.windows = NULL)
})

test_that("Option encoding unset and env set returns env encoding", {
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = 'utf-8')
  encoding = get_encoding_opt()
  expect_equal(encoding, 'utf-8')
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = '')
})

test_that("Option encoding set and env var set and EQUAL returns expected value", {
  options(keyring.encoding.windows = 'utf-16le')
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = 'utf-16le')
  encoding = get_encoding_opt()
  expect_equal(encoding, 'utf-16le')
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = '')
})

test_that("Invalid encoding (not in iconvlist) returns error", {
  options(keyring.encoding.windows = 'Omicron Persei 8')
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = 'Omicron Persei 8')
  expect_error(get_encoding_opt())
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = '')
})

test_that("iconv suggestion works as expected", {
  options(keyring.encoding.windows = 'utf-16lp')
  expect_message(
    object = expect_error(get_encoding_opt()),
    regexp = "Encoding not found in iconvlist(). Did you mean UTF-16LE?",
    fixed = TRUE
  )
  options(keyring.encoding.windows = NULL)
})

test_that("Having two different encodings set between opt and env return error", {
  options(keyring.encoding.windows = 'x_Chinese-Eten')
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = 'latin9')
  expect_error(get_encoding_opt())
  options(keyring.encoding.windows = NULL)
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = '')
})

context("Testing compatibility with python keyring package")

reticulate::use_condaenv('keyring', required = TRUE)
pyring <- reticulate::import('keyring')

test_that("Setting key with R cannot be read using python under default settings (encoding mismatches)", {
  # Set with R, default settings
  keyring::key_set_with_value(service = "testService", username = "testUser", password = "test123")
  keyring::key_get(service = "testService", username = "testUser")

  # Read with Python. Because Python sets and gets passwords encoded with UTF-16LE, this should fail.
  expect_error(pyring$get_password(":testService:testUser", username = "testUser"))
})

test_that("Setting key with python can be read using R", {
  # Python sets keys UTF-16LE encoded by default, but the R keyring package can handle that.
  pyring$set_password(":testPython:testUser", "testUser", "test123")
  expect_equal(keyring::key_get(service = "testPython", username = "testUser"), 'test123')
})

test_that("Reading UTF-16LE with encoding specified as UTF-8 will fail", {
  # This shows that the encoding options are working, and being applied. The
  # repeated lines below use various casing to ensure that casing doesn't
  # matter.
  encodings = c("UTF-8", "uTF-8", "UTf-8")

  test_env_encoding <- function(encoding) {
    Sys.setenv("KEYRING_ENCODING_WINDOWS" = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_error(test_env_encoding(e))
  }

  # Reset
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
  # Use system options now.
  test_opt_encoding <- function(encoding) {
    options(keyring.encoding.windows = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_error(test_opt_encoding(e))
  }

  # Reset
  options(keyring.encoding.windows = NULL)

})

test_that("Reading UTF-16LE with encoding specified as UTF-16LE will work", {
  # This shows that the encoding options are working, and being applied. The
  # repeated lines below use various casing to ensure that casing doesn't
  # matter.
  encodings = c("UTF-16LE", "uTF-16LE", "UTf16le", 'utf-16le')

  test_env_encoding <- function(encoding) {
    Sys.setenv("KEYRING_ENCODING_WINDOWS" = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_equal(test_env_encoding(e), 'test123')
  }

  # Reset
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
  # Use system options now.
  test_opt_encoding <- function(encoding) {
    options(keyring.encoding.windows = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_equal(test_env_encoding(e), 'test123')
  }

})

test_that("Any arbitrary key set by python can be read using R, not necessarily of the same form of this keyring API", {
  pyring$set_password("testPython", "testUser", "test123")
  pass <- keyring:::b_wincred_i_get(target = "testPython")
  expect_equal(iconv(list(pass), from = 'UTF-16LE', to = ''), "test123")
})

test_that("Set key with UTF-16LE encoding", {
  # Now, set a key with UTF-16LE encoding using new options
})

test_that("Python can read from UTF-16LE encoded key set with R", {
  # Python should be able to read from this.
})

test_that("R can read from UTF-16LE encoded key set with R", {
  # R should also still be able to read from this.
})

key_delete(service = "testService", username = "testUser")
