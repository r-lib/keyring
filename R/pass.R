
## The second prompt is to work around a getPass bug

get_pass <- function(prompt = "Password: ") {
  res <- getPass::getPass(msg = prompt)
  if (is.null(res)) {
    res <- getPass::getPass(msg = prompt)
  }
  res
}
