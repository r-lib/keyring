
backend_secret_service <- function() {
  make_backend(
    name = "secret service",
    get = backend_secret_service_get,
    set = backend_secret_service_set,
    set_with_value = backend_secret_service_set_with_value,
    delete = backend_secret_service_delete,
    list = backend_secret_service_list,
    create_keyring = backend_secret_service_create
  )
}

backend_secret_service_get <- function(backend, service, username) {
  .Call("keyring_secret_service_get", service, username,
        PACKAG = "keyring")
}

backend_secret_service_set <- function(backend, service, username) {
  ps <- get_pass()
  backend_secret_service_set_with_value(backend, service, username, pw)
}

backend_secret_service_set_with_value <- function(backend, service,
                                                  username, password) {
  .Call("keyring_secret_service_set", service, username, password,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_delete <- function(backend, service, username) {
  .Call("keyring_secret_service_delete", service, username,
        PACKAGE = "keyring")
  invisible()
}

backend_secret_service_list <- function(backend, service) {
  as.data.frame(
    .Call("keyring_secret_service_list", service, PACKAGE = "keyring"),
    col.names = c("service", "username"),
    stringsAsFactors = FALSE
  )
}
