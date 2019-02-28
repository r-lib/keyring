get_pass <- function(prompt = "Password: ") {
  names(prompt) <- Sys.info()[['user']]
  askpass::askpass(prompt = prompt)
}
