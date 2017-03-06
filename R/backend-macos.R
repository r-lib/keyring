
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
#' @include backend-class.R
#' @export

backend_macos <- R6Class(
  "backend_macos",
  inherit = backend_keyrings,
  public = list(
    name = "macos",
    initialize = function(keyring = NULL)
      b_macos_init(self, private, keyring),
    
    get = function(service, username = NULL, keyring = NULL)
      b_macos_get(self, private, service, username, keyring),
    set = function(service, username = NULL, keyring = NULL)
      b_macos_set(self, private, service, username, keyring),
    set_with_value = function(service, username = NULL, password = NULL,
      keyring = NULL)
      b_macos_set_with_value(self, private, service, username, password,
                             keyring),
    delete = function(service, username = NULL, keyring = NULL)
      b_macos_delete(self, private, service, username, keyring),
    list = function(service = NULL, keyring = NULL)
      b_macos_list(self, private, service, keyring),

    keyring_create = function(keyring)
      b_macos_keyring_create(self, private, keyring),
    keyring_list = function()
      b_macos_keyring_list(self, private),
    keyring_delete = function(keyring = NULL)
      b_macos_keyring_delete(self, private, keyring),
    keyring_lock = function(keyring = NULL)
      b_macos_keyring_lock(self, private, keyring),
    keyring_unlock = function(keyring = NULL, password = NULL)
      b_macos_keyring_unlock(self, private, keyring, password),
    keyring_default = function()
      b_macos_keyring_default(self, private),
    keyring_set_default = function(keyring = NULL)
      b_macos_keyring_set_default(self, private, keyring)
  ),

  private = list(
    keyring = NULL,
    keyring_file = function(name)
      b_macos_keyring_file(self, private, name),
    keyring_create_direct = function(keyring, password)
      b_macos_keyring_create_direct(self, private, keyring, password)
  )
)

b_macos_init <- function(self, private, keyring) {
  private$keyring <- keyring
  invisible(self)
}
    
b_macos_get <- function(self, private, service, username, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_get", utf8(keyring), utf8(service),
        utf8(username), PACKAGE = "keyring")
}

b_macos_set <- function(self, private, service, username, keyring) {
  password <- get_pass()
  b_macos_set_with_value(self, private, service, username, password, keyring)
  invisible(self)
}

b_macos_set_with_value <- function(self, private, service, username,
                                   password, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_set", utf8(keyring), utf8(service),
        utf8(username), password, PACKAGE = "keyring")
  invisible(self)
}

b_macos_delete <- function(self, private, service, username, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_delete", utf8(keyring), utf8(service),
        utf8(username), PACKAGE = "keyring")
  invisible(self)
}

b_macos_list <- function(self, private, service, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  res <- .Call("keyring_macos_list", utf8(keyring), utf8(service),
               PACKAGE = "keyring")
  data.frame(
    service = res[[1]],
    username = res[[2]],
    stringsAsFactors = FALSE
  )
}

b_macos_keyring_create <- function(self, private, keyring) {
  password <- get_pass()
  private$keyring_create_direct(keyring, password)
  invisible(self)
}

b_macos_keyring_list <- function(self, private) {
  res <- .Call("keyring_macos_list_keyring", PACKAGE = "keyring")
  data.frame(
    keyring = sub("\\.keychain$", "", basename(res[[1]])),
    num_secrets = res[[2]],
    locked = res[[3]],
    stringsAsFactors = FALSE
  )
}

b_macos_keyring_delete <- function(self, private, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_delete_keyring", utf8(keyring), PACKAGE = "keyring")
  invisible(self)
}

b_macos_keyring_lock <- function(self, private, keyring) {
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_lock_keyring", utf8(keyring), PACKAGE = "keyring")
  invisible(self)
}

b_macos_keyring_unlock <- function(self, private, keyring, password) {
  password <- password %||% get_pass()
  keyring <- private$keyring_file(keyring %||% private$keyring)
  .Call("keyring_macos_unlock_keyring", utf8(keyring), password,
        PACKAGE = "keyring")
  invisible(self)
}

b_macos_keyring_default <- function(self, private) {
  private$keyring
}

b_macos_keyring_set_default <- function(self, private, keyring) {
  private$keyring <- keyring
  invisible(self)
}

## --------------------------------------------------------------------
## Private

b_macos_keyring_file <- function(self, private, name) {
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

b_macos_keyring_create_direct <- function(self, private, keyring, password) {
  keyring <- private$keyring_file(keyring)
  .Call("keyring_macos_create", utf8(keyring), password, PACKAGE = "keyring")
  invisible(self)
}