
backend_macos <- function() {
  make_backend(
    name = "macos",
    get = backend_macos_get,
    set = backend_macos_set,
    set_with_value = backend_macos_set_with_value,
    delete = backend_macos_delete,
    list = backend_macos_list
  )
}

backend_macos_get <- function(service, username) {
  .Call("keyring_macos_get", service, username, PACKAGE = "keyring")
}

backend_macos_set <- function(service, username) {
  pw <- get_pass()
  backend_macos_set_with_value(service, username, pw)
}

backend_macos_set_with_value <- function(service, username, password) {
  .Call("keyring_macos_set", service, username, password,
        PACKAGE = "keyring")
  invisible()
}

backend_macos_delete <- function(service, username) {
  .Call("keyring_macos_delete", service, username, PACKAGE = "keyring")
  invisible()
}

backend_macos_list <- function(service) {
  ## TODO
}
