

#' AWS Secrets Manager keyring backend
#'
#' This backend must be selected explicitly. It makes calls to the AWS
#' secretsmanager service.
#'
#' This backend does not support keyrings or user names.  The call to the
#' AWS service is authenticated by either the user's ceedentials or the IAM
#' user associated with the process, for example in a docker container.
#'
#' Note that the AWS APIs provide enventual consistency, it can take
#' a noticeable amount of time, up to five minutes, for updates and deletes
#' to propagate and so code that updates, deletes and lists needs to be
#' written to tolerate that.
#'
#'
#' @family keyring backends
#' @export
#' @include backend-class.R
#' @examples
#' \dontrun{
#' ##
#' kb <- backend_awssecretsmanager$new()
#' kb$set_with_value("service", password = "secret")
#' kb$get("service")
#' kb$delete("service")
#' }

backend_awssecretsmanager <- R6Class(
  "backend_awssecretsmanager",
  inherit = backend_keyrings,
  public = list(
    name = "aws",
    initialize = function(keyring = NULL)
      b_aws_init(self, private, keyring),

    get = function(service,
                   username = NULL,
                   keyring = NULL)
      b_aws_get(self, private, service, username, keyring),
    get_raw = function(service,
                       username = NULL,
                       keyring = NULL)
      b_aws_get_raw(self, private, service, username, keyring),
    set = function(service,
                   username = NULL,
                   keyring = NULL,
                   prompt = "Password: ")
      b_aws_set(self, private, service, username, keyring, prompt),
    set_with_value = function(service,
                              username = NULL,
                              password = NULL,
                              keyring = NULL)
      b_aws_set_with_value(self, private, service, username, password,
                           keyring),
    set_with_raw_value = function(service,
                                  username = NULL,
                                  password = NULL,
                                  keyring = NULL)
      b_aws_set_with_raw_value(self, private, service, username, password,
                               keyring),
    delete = function(service,
                      username = NULL,
                      keyring = NULL)
      b_aws_delete(self, private, service, username, keyring),
    list = function(service = NULL, keyring = NULL)
      b_aws_list(self, private, service, keyring),
    is_available = function(report_error = FALSE)
      b_aws_is_available(self, private, report_error),

    has_keyring_support = function()
    {
      return(FALSE)
    },

    docs = function() {
      modifyList(super$docs(),
                 list(. = "Store secrets using the AWS Secrets manager."))
    }
  ),

  private = list(
    keyring = NULL,
    sservice = NULL,
    requestToken = paste("123456789012345678901234567890", as.character(Sys.time())),
    keyring_create_direct = function(keyring, password = NULL)
      b_aws_keyring_create_direct(self, private, keyring, password)
  )
)

b_aws_init <- function(self, private, keyring) {
  if (!is.null(keyring))
    stop("keyring parameter is not supported by the aws secrets manager backend")
  private$sservice <- paws::secretsmanager()
  invisible(self)
}

b_aws_get <- function(self, private, service, username, keyring) {
  if (!is.null(username))
    stop("username parameter is not supported by the aws secrets manager backend")
  if (!is.null(keyring))
    stop("keyring parameter is not supported by the aws secrets manager backend")
  return(private$sservice$get_secret_value(SecretId = service,)$SecretString)
}

b_aws_get_raw <-
  function(self, private, service, username, keyring) {
    if (!is.null(username))
      stop("username parameter is not supported by the aws secrets manager backend")
    if (!is.null(keyring))
      stop("keyring parameter is not supported by the aws secrets manager backend")
    return(private$sservice$svc$get_secret_value(SecretId = service,)$SecretBinary)
  }

b_aws_set <-
  function(self,
           private,
           service,
           username,
           keyring,
           prompt) {
    if (!is.null(username))
      stop("username parameter is not supported by the aws secrets manager backend")
    if (!is.null(keyring))
      stop("keyring parameter is not supported by the aws secrets manager backend")
    username <- username %||% getOption("keyring_username")
    password <- get_pass(prompt)
    if (is.null(password))
      stop("No secret provided")
    private$sservice$create_secret(
      ClientRequestToken = private$requestToken,
      Description = "",
      Name = service,
      SecretString = password
    )
    invisible(self)
  }

b_aws_set_with_value <-
  function(self,
           private,
           service,
           username,
           password,
           keyring) {
    if (!is.null(username))
      stop("username parameter is not supported by the aws secrets manager backend")
    if (!is.null(keyring))
      stop("keyring parameter is not supported by the aws secrets manager backend")
    username <- username %||% getOption("keyring_username")
    keyring <- keyring %||% private$keyring
    private$sservice$create_secret(
      ClientRequestToken = private$requestToken,
      Description = "",
      Name = service,
      SecretString = password
    )
    invisible(self)
  }

b_aws_set_with_raw_value <-
  function(self,
           private,
           service,
           username,
           password,
           keyring) {
    if (!is.null(username))
      stop("username parameter is not supported by the aws secrets manager backend")
    if (!is.null(keyring))
      stop("keyring parameter is not supported by the aws secrets manager backend")
    username <- username %||% getOption("keyring_username")
    keyring <- keyring %||% private$keyring
    private$sservice$create_secret(
      ClientRequestToken = private$requestToken,
      Description = "",
      Name = service,
      SecretBinaryString = password
    )
    invisible(self)
  }

b_aws_delete <-
  function(self, private, service, username, keyring) {
    if (!is.null(username))
      stop("username parameter is not supported by the aws secrets manager backend")
    if (!is.null(keyring))
      stop("keyring parameter is not supported by the aws secrets manager backend")
    username <- username %||% getOption("keyring_username")
    keyring <- keyring %||% private$keyring
    private$sservice$delete_secret(ForceDeleteWithoutRecovery = TRUE,
                                   SecretId = service)
    invisible(self)
  }

b_aws_list <- function(self, private, service, keyring) {
  if (!is.null(keyring))
    stop("keyring parameter is not supported by the aws secrets manager backend")
  keyring <- keyring %||% private$keyring
  if (is.null(service) ||
      service == "")
    # missing defaults to null in calling routine
  {
    res = private$sservice$list_secrets()
  } else
  {
    res = private$sservice$list_secrets(Filter = list(list(
      Key = "name", Values = c(service)
    )))
  }
  nameList = c()
  if (length(res$SecretList) > 0)
  {
    for (i in 1:length(res$SecretList))
    {
      nameList = c(nameList, res$SecretList[[i]]$Name)
    }
  }
  df = data.frame(service = nameList,
                  stringsAsFactors = FALSE)
  df$username = NULL

  return(df)
}

b_aws_is_available <- function(self, private, report_error) {
  if(!requireNamespace("paws"))
  {
    if(report_error)
    {
      signalCondition("Paws library not available.  It is required for AWS access")
    }
    return(FALSE)
  }
  callerID = try(paws::sts()$get_caller_identity())
  if (inherits(callerID, "try-error")) {
    if(report_error)
    {
      signalCondition("No AWS credentials to use for testing or AWS not reachable")
    }
    return(FALSE)
  }
  return(TRUE)
  }

