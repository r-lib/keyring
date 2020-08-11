
#' Query, set, delete, and list keys in Windows Credential Manager
#'
#' These functions directly manipulate keys in the Windows Credential Manager
#' (WCM), bypassing the common API. Multiple keyrings are not supported, and
#' only one set of credentials (username/password) can be assigned for any
#' particular service.
#'
#' `wincred_get` retrieves a password from WCM; if `username` is specified, it
#' only returns the password if the username matches the one for the specified
#' `service` in WCM.
#'
#' `wincred_get_username` retrieves a username from WCM.
#'
#' `wincred_get_raw` queries a password and returns it as a raw vector. Most
#' credential stores allow storing a byte sequence with embedded null bytes, and
#' these cannot be represented as traditional null bytes terminated strings. If
#' you don't know whether the key contains an embedded null, it is best to query
#' it with `wincred_get_raw` instead of `wincred_get`.
#'
#' `wincred_set` sets a credential (service, username, and password) in WCM. The
#' contents of the password are read interactively from the terminal. If a
#' credential already exists for the specified `service`, it will be
#' overwritten, even if the `username` is different.
#'
#' `wincred_set_with_value` is the non-interactive pair of `wincred_set`, to set
#' a credential in WCM.
#'
#' `wincred_set_raw_with_value` sets a credential; the password is set to a byte
#' sequence from a raw vector.
#'
#' `wincred_delete` deletes a credential.
#'
#' `wincred_list` lists all services in WCM if `service` is `NULL`; if `service`
#' is not `NULL`, it returns `service` if the service is present in WCM, or
#' `character(0)` if it is not present.
#'
#' @param service Service name, a character scalar.
#' @param username Username, a character scalar, or `NULL` if the key is not
#'   associated with a username.
#' @param password The secret to store. For `wincred_set`, it is read from the
#'   console, interactively. `wincred_set_with_value` and
#'   `wincred_set_raw_with_value` can also be used in non-interactive mode.
#' @return `wincred_get` returns a character scalar of the password stored in
#'   the credential.
#'
#'   `wincred_get_username` returns a character scalar of the username stored in
#'   the credential.
#'
#'   `wincred_list` returns a list of credentials, i.e. service names.
#'
#'
#' @export
#' @examples
#' # These examples use WCM, and they are interactive, so we don't run them by default/
#' \dontrun{
#' wincred_set("R-keyring-test-service", "donaldduck")
#' wincred_get_username("R-keyring-test-service")
#' wincred_get("R-keyring-test-service", "donaldduck")
#' wincred_list(service = "R-keyring-test-service")
#' wincred_delete("R-keyring-test-service", "donaldduck")
#'
#' ## This is non-interactive
#' wincred_set_with_value("R-keyring-test-service", "donaldduck",
#'                        password = "secret")
#' wincred_get_username("R-keyring-test-service")
#' wincred_get("R-keyring-test-service", "donaldduck")
#' wincred_list(service = "R-keyring-test-service")
#' wincred_delete("R-keyring-test-service", "donaldduck")

wincred_get <- function(service, username = NULL) {
  password <- wincred_get_raw(service, username)

  if (any(password == 0)) {
    password <- iconv(list(password), from = "UTF-16LE", to = "")
    if (is.na(password)) {
      stop("Key contains embedded null bytes, use wincred_get_raw()")
    }
    password
  } else {
    rawToChar(password)
  }
}

#' @export
#' @rdname wincred_get

wincred_get_raw <- function(service, username = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))
  user <- ifelse(is.null(username), "", username)
  .Call("keyring_wincred_get_native", service, user)
}

#' @export
#' @rdname wincred_get

wincred_get_username <- function(service) {
  assert_that(is_non_empty_string(service))
  .Call("keyring_wincred_get_username", service)
}

#' @export
#' @rdname wincred_get

wincred_set <- function(service, username = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string(username))
  password <- get_pass()
  wincred_set_with_value(service, username, password)
}

#' @export
#' @rdname wincred_get

wincred_set_with_value <- function(service, username = NULL, password = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string(username))
  assert_that(is_string(password))
  wincred_set_with_raw_value(service, username, charToRaw(password))
}

#' @export
#' @rdname wincred_get

wincred_set_with_raw_value <- function(service, username = NULL, password = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string(username))
  assert_that(is.raw(password))
  .Call("keyring_wincred_set", service, password, username, FALSE)
  invisible()
}

#' @export
#' @rdname wincred_get

wincred_delete <- function(service, username = NULL) {
  assert_that(is_non_empty_string(service))
  assert_that(is_string_or_null(username))

  if (!is.null(username) && username != wincred_get_username(service)) {
    stop("Specified username does not match credential's username.")
  }

  .Call("keyring_wincred_delete", service)
  invisible()
}

#' @export
#' @rdname wincred_get

wincred_list <- function(service = NULL) {
  filter <- if (is.null(service)) {
    "*"
  } else {
    service
  }
  .Call("keyring_wincred_enumerate", filter)
}
