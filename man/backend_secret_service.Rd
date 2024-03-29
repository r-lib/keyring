% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/backend-secret-service.R
\name{backend_secret_service}
\alias{backend_secret_service}
\title{Linux Secret Service keyring backend}
\description{
This backend is the default on Linux. It uses the libsecret library,
and needs a secret service daemon running (e.g. Gnome Keyring, or
KWallet). It uses DBUS to communicate with the secret service daemon.
}
\details{
This backend supports multiple keyrings.

See \link{backend} for the documentation of the individual methods.
The \code{is_available()} method checks is a Secret Service daemon is
running on the system, by trying to connect to it. It returns a logical
scalar, or throws an error, depending on its argument:

\if{html}{\out{<div class="sourceCode">}}\preformatted{is_available = function(report_error = FALSE)
}\if{html}{\out{</div>}}

Argument:
\itemize{
\item \code{report_error} Whether to throw an error if the Secret Service is
not available.
}
}
\examples{
\dontrun{
## This only works on Linux, typically desktop Linux
kb <- backend_secret_service$new()
kb$keyring_create("foobar")
kb$set_default_keyring("foobar")
kb$set_with_value("service", password = "secret")
kb$get("service")
kb$delete("service")
kb$delete_keyring("foobar")
}
}
\seealso{
Other keyring backends: 
\code{\link{backend_env}},
\code{\link{backend_file}},
\code{\link{backend_macos}},
\code{\link{backend_wincred}}
}
\concept{keyring backends}
