
skip_if_not_macos <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])
  if (sysname != "darwin") skip("Not macOS")
  invisible(TRUE)
}

skip_if_not_win <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])
  if (sysname != "windows") skip("Not windows")
  invisible(TRUE)
}

skip_if_not_linux <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])
  if (sysname != "linux") skip("Not Linux")
  invisible(TRUE)
}

skip_if_not_secret_service <- function() {
  if (default_backend()$name != "secret service") skip("Not secret service")
  invisible(TRUE)
}

random_string <- function(length = 10, use_letters = TRUE,
                          use_numbers = TRUE) {
  pool <- c(
    if (use_letters) c(letters, LETTERS),
    if (use_numbers) 0:9
  )
  paste(
    sample(pool, length, replace = TRUE),
    collapse = ""
  )
}

random_service <- function() {
  paste0(
    "R-keyring-test-service-",
    random_string(15, use_numbers = FALSE)
  )
}

random_username <- function() {
  random_string(10, use_numbers = FALSE)
}

random_password <- function() {
  random_string(16)
}

random_keyring <- function() {
  paste0(
    "Rkeyringtest",
    random_string(8, use_numbers = FALSE)
  )
}

new_empty_dir <- function() {
  new <- tempfile()
  unlink(new, recursive = TRUE, force = TRUE)
  dir.create(new)
  new
}
