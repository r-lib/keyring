
context("default backend")

opts <- options(keyring_warn_for_env_fallback = FALSE)
on.exit(options(opts), add = TRUE)

test_that("use options", {
  withr::with_options(
    list(keyring_backend = "env"),
    expect_equal(default_backend(), backend_env$new())
  )
  withr::with_options(
    list(keyring_backend = "env"),
    expect_equal(default_backend(), backend_env$new())
  )
  ## This should run on all OSes currently, as we are not actually
  ## calling the Keychain API here.
  withr::with_options(
    list(keyring_backend = "macos", keyring_keyring = "foobar"),
    expect_equal(default_backend(), backend_macos$new(keyring = "foobar"))
  )
})

test_that("use env var", {
  ## Remove the options
  withr::with_options(
    list(keyring_backend = NULL, keyring_keyring = NULL),
    withr::with_envvar(
      c(R_KEYRING_BACKEND = "env"),
      expect_equal(default_backend(), backend_env$new())
    )
  )
})

test_that("mixing options and env vars", {
  ## Backend option, keyring env var
  withr::with_options(
    list(keyring_backend = "macos", keyring_keyring = NULL),
    withr::with_envvar(
      c(R_KEYRING_KEYRING = "foobar"),
      expect_equal(default_backend(), backend_macos$new(keyring = "foobar"))
    )
  )

  ## Backend env var, keyring option
  withr::with_options(
    list(keyring_backend = NULL, keyring_keyring = "foobar"),
    withr::with_envvar(
      c(R_KEYRING_BACKEND = "macos"),
      expect_equal(default_backend(), backend_macos$new(keyring = "foobar"))
    )
  )
})

test_that("auto windows", {
  mockery::stub(default_backend_auto, "Sys.info", c(sysname = "Windows"))
  expect_equal(default_backend_auto(), backend_wincred)
})

test_that("auto macos", {
  mockery::stub(default_backend_auto, "Sys.info", c(sysname = "Darwin"))
  expect_equal(default_backend_auto(), backend_macos)
})

test_that("auto linux", {
  skip_if_not_linux()  
  kb <- default_backend()
  expect_true(kb$name == "env" || kb$name == "secret service")
})

test_that("auto other", {
  mockery::stub(default_backend_auto, "Sys.info", c(sysname = "Solaris"))
  expect_equal(suppressWarnings(default_backend_auto()), backend_env)
})
