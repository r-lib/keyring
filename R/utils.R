
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

get_encoding_opt <- function() {
  opt_encoding <- getOption("keyring.encoding.windows")
  if (length(opt_encoding) == 0) opt_encoding <- "auto"
  env_encoding <- Sys.getenv("KEYRING_ENCODING_WINDOWS")
  if (env_encoding == "") env_encoding <- "auto"
  # Handle differing values if one or the other is not auto -- stop in this case
  if (opt_encoding != env_encoding & !(opt_encoding == "auto" | env_encoding == "auto")) {
    message(sprintf("Sys.getenv('KEYRING_ENCODING_WINDOWS'):\t'%s'", env_encoding))
    message(sprintf("getOption(keyring.encoding.windows):\t'%s'", opt_encoding))
    stop("Mismatch in keyring encoding settings; value set with both an environment variable and R option.\nChange environment variable with Sys.setenv('KEYRING_ENCODING_WINDOWS' = 'encoding_type'),\nand R option with options(keyring.encoding.windows = 'encoding_type') to match.")
  }
  # If one and only one is auto, then one of these was set deliberately; respect this
  if (xor(opt_encoding == "auto", env_encoding == "auto")) {
    # Encoding is whichever one that is not auto.
    encodings <- c(opt_encoding, env_encoding)
    encoding <- encodings[encodings != "auto"]
  }
  # If both the same:
  if (opt_encoding == env_encoding) {
    # And they're auto, then auto
    if (opt_encoding == "auto") {
      encoding <- "auto"
    } else {
      # Otherwise, the encoding is either one
      encoding <- opt_encoding
    }
  }
  # Confirm valid encoding. Suggest closest match if not found.
  if (encoding != "auto" & !(tolower(encoding) %in% tolower(iconvlist()))) {
    closest_match <- iconvlist()[
      which.min(adist(encoding, iconvlist()))
    ]
    message(sprintf("Encoding not found in iconvlist(). Did you mean %s?", closest_match))
    stop("Supplied invalid encoding.")
  }
  encoding
}

is_interactive <- function() {
  opt <- getOption("rlib_interactive")
  if (isTRUE(opt)) {
    TRUE
  } else if (identical(opt, FALSE)) {
      FALSE
  } else if (tolower(getOption("knitr.in.progress", "false")) == "true") {
    FALSE
  } else if (tolower(getOption("rstudio.notebook.executing", "false")) == "true") {
    FALSE
  } else if (identical(Sys.getenv("TESTTHAT"), "true")) {
    FALSE
  } else {
    interactive()
  }
}
