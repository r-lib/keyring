
utf8 <- function(x) {
  if (is.null(x)) return(x)
  iconv(x, "", "UTF-8")
}

`%||%` <- function(l, r) if (is.null(l)) r else l

cat0 <- function(..., sep = "") {
  cat(..., sep = sep)
}

confirmation <- function(prompt, yes) {
  ans <- readline(paste0(prompt, ": "))
  if (ans != yes) stop("Aborted", call. = FALSE)
}

darwin_version <- function() {
  info <- Sys.info()
  if (info[["sysname"]] != "Darwin") stop("Not macOS")
  package_version(info[["release"]])
}
