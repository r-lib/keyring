
abstract_method <- function() {
  stop("An abstract keyring method is called. This is an internal error. ",
       "It most likely happends because of a broken keyring backend that ",
       "does not implement all keyring functions.")
}

#' @importFrom R6 R6Class
#' @export

backend <- R6Class(
  "backend",
  public = list(
    name = "Unknown keyring backend",

    has_keyring_support = function() FALSE,

    get = function(service, username = NULL, keyring = NULL)
      abstract_method(),
    set = function(service, username = NULL, keyring = NULL)
      abstract_method(),
    set_with_value = function(service, username = NULL, password = NULL,
                              keyring = NULL)
      abstract_method(),
    delete = function(service, username = NULL, keyring = NULL)
      abstract_method(),
    list = function(service = NULL, keyring = NULL)
      stop("Backend does not implement 'list'")
  )
)

#' @export

backend_keyrings <- R6Class(
  "backend_keyrings",
  inherit = backend,
  public = list(
    has_keyring_support = function() TRUE,

    get = function(service, username = NULL, keyring = NULL)
      abstract_method(),
    set = function(service, username = NULL, keyring = NULL)
      abstract_method(),
    set_with_value = function(service, username = NULL, password = NULL,
      keyring = NULL)
      abstract_method(),
    delete = function(service, username = NULL)
      abstract_method(),
    list = function(service = NULL, keyring = NULL)
      abstract_method(),

    keyring_create = function(keyring) abstract_method(),
    keyring_list = function() abstract_method(),
    keyring_delete = function(keyring = NULL) abstract_method(),
    keyring_lock = function(keyring = NULL) abstract_method(),
    keyring_unlock = function(keyring = NULL, password = NULL)
      abstract_method(),
    keyring_default = function() abstract_method(),
    keyring_set_default = function(keyring = NULL) abstract_method()
  )
)
