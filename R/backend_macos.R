
#' Create a macOS Keychain backend
#'
#' This backend is the default on macOS. It uses the macOS native Keychain
#' Service API.
#'
#' It supports multiple keyrings.
#' @param keyring Name of the keyring to use. `NULL` specifies the
#'   default keyring.
#' @return A backend object that can be used in `keyring` functions.
#'
#' @family keyring backends
#' @export

backend_macos <- function(keyring = NULL) {
  assert_that(is_string_or_null(keyring))
  make_backend(
    name = "macos",
    keyring = backend_macos_keyring_file(keyring),
    get = backend_macos_get,
    set = backend_macos_set,
    set_with_value = backend_macos_set_with_value,
    delete = backend_macos_delete,
    list = backend_macos_list,
    create_keyring = backend_macos_create_keyring,
    list_keyring = backend_macos_list_keyring,
    delete_keyring = backend_macos_delete_keyring,
    lock_keyring = backend_macos_lock_keyring,
    unlock_keyring = backend_macos_unlock_keyring
  )
}

backend_macos_keyring_file <- function(name) {
  if (is.null(name)) {
    name

  } else if (substr(name, 1, 1) == "/" || substr(name, 1, 2) == "./") {
    normalizePath(name, mustWork = FALSE)

  } else {
    normalizePath(
      paste0("~/Library/Keychains/", name, ".keychain"),
      mustWork = FALSE
    )
  }
}

backend_macos_get <- function(backend, service, username) {
  .Call("keyring_macos_get", utf8(backend$keyring), utf8(service),
        utf8(username), PACKAGE = "keyring")
}

backend_macos_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_macos_set_with_value(backend, service, username, pw)
}

backend_macos_set_with_value <- function(backend, service, username,
                                         password) {
  .Call("keyring_macos_set", utf8(backend$keyring), utf8(service),
        utf8(username), password, PACKAGE = "keyring")
  invisible()
}

backend_macos_delete <- function(backend, service, username) {
  .Call("keyring_macos_delete", utf8(backend$keyring), utf8(service),
        utf8(username), PACKAGE = "keyring")
  invisible()
}

backend_macos_list <- function(backend, service) {
  res <- .Call("keyring_macos_list", utf8(backend$keyring), utf8(service),
               PACKAGE = "keyring")
  data.frame(
    service = res[[1]],
    username = res[[2]],
    stringsAsFactors = FALSE
  )
}

backend_macos_create_keyring <- function(backend) {
  pw <- get_pass()
  backend_macos_create_keyring_direct(backend$keyring, pw)
}

backend_macos_create_keyring_direct <- function(keyring, pw = NULL) {
  .Call("keyring_macos_create", utf8(keyring), pw, PACKAGE = "keyring")
  invisible()
}

backend_macos_list_keyring <- function(backend) {
  res <- .Call("keyring_macos_list_keyring", PACKAGE = "keyring")
  data.frame(
    keyring = sub("\\.keychain$", "", basename(res[[1]])),
    num_secrets = res[[2]],
    locked = res[[3]],
    stringsAsFactors = FALSE
  )
}

backend_macos_delete_keyring <- function(backend) {
  .Call("keyring_macos_delete_keyring", utf8(backend$keyring),
        PACKAGE = "keyring")
  invisible()
}

backend_macos_lock_keyring <- function(backend) {
  .Call("keyring_macos_lock_keyring", utf8(backend$keyring), PACKAGE = "keyring")
  invisible()
}

backend_macos_unlock_keyring <- function(backend, password = NULL) {
  if (is.null(password)) password <- get_pass()
  .Call("keyring_macos_unlock_keyring", utf8(backend$keyring), password,
        PACKAGE = "keyring")
  invisible()
}
