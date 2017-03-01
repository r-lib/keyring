
#' @export

print.keyring_backend <- function(x, ...) {
  cat("[Keyring backend ", sQuote(x$name), "]\n", sep = "")
  all_ops <- setdiff(names(x), "keyring")
  key_ops <- intersect(
    all_ops,
    c("set", "get", "set_with_value", "list", "delete")
  )
  keyring_ops <- intersect(
    all_ops,
    c("keyring_create", "keyring_list", "keyring_delete", "keyring_lock",
      "keyring_unlock")
  )
  other_ops <- setdiff(all_ops, c(key_ops, keyring_ops))

  cat("* Operations:", paste(key_ops, collapse = ", "), "\n")
  if (keyring_support(x)) {
    s <- paste0(
      "* Supports multiple keyrings: ",
      paste(keyring_ops, collapse = ", ")
    )
    cat(strwrap(s, indent = 0, exdent = 2), sep = "\n")
  }

  invisible(x)
}
