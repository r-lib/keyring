# Setup ------------------------------------------------------------------------

library(reticulate)
library(keyring)

reticulate::use_condaenv('keyring', required = TRUE)
pyring <- reticulate::import('keyring')

context("Testing compatibility with python keyring package")

test_that("Setting key with R can be read using python", {
  # Set with R, default settings
  keyring::key_set_with_value(service = "testService", username = "testUser", password = "test123")
  keyring::key_get(service = "testService", username = "testUser")

  # Read with Python. Because Python sets and gets passwords encoded with UTF-16LE, this should fail.
  expect_error(pyring$get_password(":testService:testUser", username = "testUser"))
})

test_that("Setting key with python can be read using R (reverse of previous)", {
  # Python sets keys UTF-16LE encoded by default, but the R keyring package can handle that.
  pyring$set_password(":testPython:testUser", "testUser", "test123")
  expect_equal(keyring::key_get(service = "testPython", username = "testUser"), 'test123')
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
