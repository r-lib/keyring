
#' Select the default backend for a platform
#'
#' TODO
#'
#' @export
#' @name backends
#' @examples
#' # TODO

default_backend <- function() {
  sysname <- tolower(Sys.info()[["sysname"]])
  if (sysname == "windows") {
    backend_wincred()
  } else if (sysname == "darwin") {
    backend_macos()
  } else {
    warning("Selecting ", sQuote(env), " backend. ",
            "Secrets are stored in environment variables")
    backend_env()
  }
}
