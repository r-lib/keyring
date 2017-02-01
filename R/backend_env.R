
#' Store secrets in environment variables
#'
#' TODO
#'
#' @family keyring backends
#' @export
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

backend_env_get <- function(service, username) {
  var <- backend_env_to_var(service, username)
  nachar_to_null(Sys.getenv(var, NA_character_))
}

backend_env_set <- function(service, username) {
  pw <- get_pass()
  backend_env_set_with_value(service, username, pw)
}

backend_env_set_with_value <- function(service, username, password) {
  var <- backend_env_to_var(service, username)
  do.call(Sys.setenv, structure(list(password), names = var))
  invisible()
}

backend_env_delete <- function(service, username) {
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
