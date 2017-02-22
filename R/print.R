
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
    c("create_keyring", "list_keyring", "delete_keyring", "lock_keyring",
      "unlock_keyring")
  )
  other_ops <- setdiff(all_ops, c(key_ops, keyring_ops))

  cat("* Operations:", paste(key_ops, collapse = ", "), "\n")
  if ("keyring" %in% names(x)) {
    s <- paste0(
      "* Supports multiple keyrings: ",
      paste(keyring_ops, collapse = ", ")
    )
    cat(strwrap(s, indent = 0, exdent = 2), sep = "\n")
  }

  invisible(x)
}
