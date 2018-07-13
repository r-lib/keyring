
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

file_stamp <- function(x) {
  as.character(tools::md5sum(x))
}

str_starts_with <- function(x, p) {
  ncp <- nchar(p)
  substr(x, 1, nchar(p)) == p
}

URLencode <- function(URL) {
  good <- c(LETTERS, letters, 0:9, ".", "_", "~", "-")
  x <- strsplit(URL, "")[[1L]]
  bad <- which(! x %in% good)
  tr <- function(x) {
    paste0("%", toupper(as.character(charToRaw(x))), collapse = "")
  }
  if (length(bad)) x[bad] <- vapply(x[bad], tr, character(1))
  paste(x, collapse = "")
}
