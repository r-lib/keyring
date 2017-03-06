
#' @importFrom assertthat on_failure<- assert_that

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
