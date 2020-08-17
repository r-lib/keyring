# Setup ------------------------------------------------------------------------

library(reticulate)
library(keyring)

# Tests ------------------------------------------------------------------------

# For now the encoding functionality and cross-compatiblity with Python is only
# supported on Windows!

context("Testing compatibility with python keyring package")

KEYRING_ENV <- "keyring37"
ENVS <- reticulate::conda_list()$name

skip_if_no_conda <- function() {
  if (!reticulate::py_available()) {
    skip("Python not available")
  }
  if (!(KEYRING_ENV %in% ENVS)) {
    skip("Conda environment not available")
  }
  invisible(TRUE)
}

if (KEYRING_ENV %in% ENVS) {
  reticulate::use_condaenv("keyring37", required = TRUE)
  pyring <- reticulate::import("keyring")
}

test_that("Setting key with R cannot be read using python under default settings (encoding mismatches)", {
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  # Set with R, default settings
  keyring::key_set_with_value(service = "testService", username = "testUser", password = "test123")
  keyring::key_get(service = "testService", username = "testUser")

  # Read with Python. Because Python sets and gets passwords encoded with UTF-16LE, this should fail.
  expect_error(pyring$get_password(":testService:testUser", username = "testUser"))
})

test_that("Setting key with python can be read using R", {
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  # Python sets keys UTF-16LE encoded by default, but the R keyring package can handle that.
  pyring$set_password(":testPython:testUser", "testUser", "test123")
  expect_equal(keyring::key_get(service = "testPython", username = "testUser"), "test123")
})

test_that("Reading UTF-16LE with encoding specified as UTF-8 will fail", {
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  # This shows that the encoding options are working, and being applied. The
  # repeated lines below use various casing to ensure that casing doesn't
  # matter.
  encodings <- c("UTF-8", "uTF-8", "UTf-8")

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
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  # This shows that the encoding options are working, and being applied. The
  # repeated lines below use various casing to ensure that casing doesn't
  # matter.
  encodings <- c("UTF-16LE", "uTF-16LE", "UTf16le", "utf-16le")

  test_env_encoding <- function(encoding) {
    Sys.setenv("KEYRING_ENCODING_WINDOWS" = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_equal(test_env_encoding(e), "test123")
  }

  # Reset
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
  # Use system options now.
  test_opt_encoding <- function(encoding) {
    options(keyring.encoding.windows = encoding)
    keyring::key_get(service = "testPython", username = "testUser")
  }

  for (e in encodings) {
    expect_equal(test_env_encoding(e), "test123")
  }
})

test_that("Any arbitrary key set by python can be read using R, not necessarily of the same form of this keyring API", {
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  pyring$set_password("testPython", "testUser", "test123")
  pass <- keyring:::b_wincred_i_get(target = "testPython")
  expect_equal(iconv(list(pass), from = "UTF-16LE", to = ""), "test123")
})

test_that("Python can read from UTF-16LE encoded key set with R", {
  skip_if_not_win()
  skip_on_cran()
  skip_if_no_conda()
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-16le")
  keyring::key_set_with_value(service = "testEncoding", username = "testUser", password = "test123")
  # Python should be able to read from this.
  expect_equal(pyring$get_password(service_name = ":testEncoding:testUser", username = "testUser"), "test123")
  Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
})

if (interactive()) {
  test_that("Password set in R using a keyring", {
    skip_if_not_win()
    skip_on_cran()
    skip_if_no_conda()
    Sys.setenv("KEYRING_ENCODING_WINDOWS" = "utf-16le")
    keyring::keyring_create("testKeyring")
    keyring::key_set_with_value(service = "testEncoding", username = "testUser", password = "test123", keyring = "testKeyring")
    expect_equal(keyring::key_get(service = "testEncoding", username = "testUser", keyring = "testKeyring"), "test123")
    Sys.setenv("KEYRING_ENCODING_WINDOWS" = "")
  })
}

# Clean up ---------------------------------------------------------------------
try(
  {
    key_delete(service = "testService", username = "testUser")
    key_delete(service = "testEncoding", username = "testUser")
    keyring:::b_wincred_i_delete()
    pyring$delete_password(service_name = "testPython", username = "testUser")
    pyring$delete_password(service_name = ":testPython:testUser", username = "testUser")
  },
  silent = TRUE
)
