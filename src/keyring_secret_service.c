
#ifdef __linux__

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <libsecret/secret.h>

void R_init_keyring(DllInfo *info) {
  g_type_ensure (G_TYPE_OBJECT);
}

void R_unload_keyring(DllInfo *info) {
  secret_service_disconnect();
 }

const SecretSchema *keyring_secret_service_schema() {
  static const SecretSchema schema = {
    "com.rstudio.keyring.password", SECRET_SCHEMA_NONE, {
      {  "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
      {  "username", SECRET_SCHEMA_ATTRIBUTE_STRING },
      {  NULL, 0 },
    }
  };

  return &schema;
}

void keyring_secret_service_handle_status(const char *func, gboolean status,
					  GError *err) {
  if (!status || err) {
    g_error_free (err);
    error("Secret service keyring error in '%s': '%s'", func, "TODO");
  }
}

SEXP keyring_secret_service_get(SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

  GError *err = NULL;

  gchar *password = secret_password_lookup_sync (
    keyring_secret_service_schema(),
    /* cancellable = */ NULL,
    &err,
    "service", cservice,
    "username", cusername,
    NULL);

  if (err) {
    if (password) secret_password_free(password);
    keyring_secret_service_handle_status("get", TRUE, err);
  }

  if (!password) {
    error("keyring item not found");
    return R_NilValue;

  } else {
    SEXP result = PROTECT(ScalarString(mkChar(password)));
    if (password) secret_password_free(password);
    UNPROTECT(1);
    return result;
  }
}

SEXP keyring_secret_service_set(SEXP service, SEXP username,
				SEXP password) {
  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  const char* cpassword = CHAR(STRING_ELT(password, 0));

  GError *err = NULL;

  gboolean status = secret_password_store_sync(
    keyring_secret_service_schema(),
    SECRET_COLLECTION_DEFAULT,
    /* label = */ "TODO",
    cpassword,
    /* cancellable = */ NULL,
    &err,
    "service", cservice,
    "username", cusername,
    NULL);

  keyring_secret_service_handle_status("set", status, err);

  return R_NilValue;
}

SEXP keyring_secret_service_delete(SEXP service, SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

  GError *err = NULL;

  gboolean status = secret_password_clear_sync(
    keyring_secret_service_schema(),
    /* cancellable = */ NULL,
    &err,
    "service", cservice,
    "username", cusername,
    NULL);

  keyring_secret_service_handle_status("get", TRUE, err);

  return R_NilValue;
}

SEXP keyring_secret_service_list(SEXP service) {
  return R_NilValue;
}

#endif // __linux__
