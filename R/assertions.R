
#' @importFrom assertthat on_failure<- assert_that has_name

is_string <- function(x) {
  is.character(x) && length(x) == 1 && !is.na(x)
}

on_failure(is_string) <- function(call, env) {
  paste0(deparse(call$x), " is not a string (length 1 character)")
}

is_string_or_null <- function(x) {
  is.null(x) || is_string(x)
}

on_failure(is_string_or_null) <- function(call, env) {
  paste0(deparse(call$x), " must be a string (length 1 character) or NULL")
}

is_non_empty_string <- function(x) {
  is_string(x) && x != ""
}

on_failure(is_non_empty_string) <- function(call, env) {
  paste0(deparse(call$x), " must be a non-empty string (length 1 character)")
}

is_non_empty_string_or_null <- function(x) {
  is.null(x) || is_non_empty_string(x)
}

on_failure(is_non_empty_string_or_null) <- function(call, env) {
  paste0(
    deparse(call$x),
    " must be a non-empty string (length 1 character) or NULL"
  )
}

is_string_or_raw <- function(x) {
  is.raw(x) || is_string(x)
}

on_failure(is_string_or_raw) <- function(call, env) {
  paste0(
    deparse(call$x),
    " must be a string (length 1 character) or raw vector"
  )
}

is_file_keyring_item <- function(x) {
  is.list(x) && length(x) == 3L &&
  has_name(x, "service_name") &&
  has_name(x, "user_name") &&
  has_name(x, "secret")
}

on_failure(is_file_keyring_item) <- function(call, env) {
  paste0(
    deparse(call$x),
    " must be a named list of length 3 with entries ",
    sQuote("service_name"), ", ",
    sQuote("user_name"), " and ",
    sQuote("secret")
  )
}

is_file_keyring_file <- function(x) {
  is.list(x) && length(x) == 2L &&
  has_name(x, "keyring_info") &&
  has_name(x, "items")
}

on_failure(is_file_keyring_file) <- function(call, env) {
  paste0(
    deparse(call$x),
    " must be a named list of length 2 with entries ",
    sQuote("keyring_info"), " and ",
    sQuote("items")
  )
}

is_file_keyring_file_header <- function(x) {
  is.list(x) && length(x) == 3L &&
  has_name(x, "keyring_version") &&
  has_name(x, "nonce") &&
  has_name(x, "integrity_check")
}

on_failure(is_file_keyring_file_header) <- function(call, env) {
  paste0(
    deparse(call$x),
    " must be a named list of length 3 with entries ",
    sQuote("keyring_version"), ", ",
    sQuote("nonce"), " and ",
    sQuote("integrity_check")
  )
}
