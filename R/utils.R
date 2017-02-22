
utf8 <- function(x) {
  if (is.null(x)) return(x)
  iconv(x, "", "UTF-8")
}

`%||%` <- function(l, r) if (is.null(l)) r else l
