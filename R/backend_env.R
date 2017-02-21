
#' Store secrets in environment variables
#'
#' TODO
#'
#' @family keyring backends
#' @examples
#' # TODO

backend_env <- function() {
  make_backend(
    name = "env",
    get = backend_env_get,
    set = backend_env_set,
    delete = backend_env_delete,
    set_with_value = backend_env_set_with_value,
    list = NULL
  )
}

backend_env_get <- function(backend, service, username) {
  var <- backend_env_to_var(service, username)
  res <- Sys.getenv(var, NA_character_)
  if (is.na(res)) stop("Cannot find password")
  res
}

backend_env_set <- function(backend, service, username) {
  pw <- get_pass()
  backend_env_set_with_value(backend, service, username, pw)
}

backend_env_set_with_value <- function(backend, service, username, password) {
  var <- backend_env_to_var(service, username)
  do.call(Sys.setenv, structure(list(password), names = var))
  invisible()
}

backend_env_delete <- function(backend, service, username) {
  var <- backend_env_to_var(service, username)
  Sys.unsetenv(var)
}

backend_env_to_var <- function(service, username) {
  if (is.null(username)) {
    service
  } else {
    paste0(service, ":", username)
  }
}
