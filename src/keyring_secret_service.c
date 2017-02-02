
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

SecretCollection* keyring_secret_service_get_collection(SEXP keyring) {

  const char* ckeyring = isNull(keyring) ? "default" : CHAR(STRING_ELT(keyring, 0));
  SecretCollection *collection = NULL;

  const char *errormsg = NULL;
  GError *err = NULL;

  SecretService *secretservice = secret_service_get_sync(
    /* flags = */ SECRET_SERVICE_LOAD_COLLECTIONS,
    /* cancellable = */ NULL,
    &err);

  if (err || !secretservice) {
    errormsg = "Cannot connect to secret service";
    goto cleanup;
  }

  collection = secret_collection_for_alias_sync(
    /* service = */ secretservice,
    /* alias = */ ckeyring,
    /* flags = */ SECRET_COLLECTION_NONE,
    /* cancellable = */ NULL,
    &err);

  if (err || !collection) {
    errormsg = "Cannot find keyring";
    goto cleanup;
  }

 cleanup:
  if (secretservice) g_object_unref(secretservice);
  keyring_secret_service_handle_status("get_keyring", TRUE, err);
  if (errormsg) error(errormsg);

  return collection;
}

GList* keyring_secret_service_get_item(SEXP keyring, SEXP service,
				       SEXP username) {

  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));

  const char *errormsg = NULL;
  SecretCollection *collection = NULL;
  GList *secretlist = NULL;
  GHashTable *attributes = NULL;
  GError *err = NULL;

  collection = keyring_secret_service_get_collection(keyring);
  attributes = g_hash_table_new(
    /* hash_func = */ (GHashFunc) g_str_hash,
    /* key_equal_func = */ (GEqualFunc) g_str_equal);

  g_hash_table_insert(attributes, g_strdup("service"), g_strdup(cservice));
  g_hash_table_insert(attributes, g_strdup("username"), g_strdup(cusername));

  secretlist = secret_collection_search_sync(
    /* self = */ collection,
    /* schema = */ keyring_secret_service_schema(),
    /* attributes = */ attributes,
    /* flags = */ SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK |
                  SECRET_SEARCH_LOAD_SECRETS,
    /* cancellable = */ NULL,
    &err);

  if (err) goto cleanup;

 cleanup:
  if (collection) g_object_unref(collection);
  if (attributes) g_hash_table_unref(attributes);
  keyring_secret_service_handle_status("get", TRUE, err);
  if (errormsg) error(errormsg);

  return secretlist;
}

SEXP keyring_secret_service_get(SEXP keyring, SEXP service, SEXP username) {

  GList *secretlist = keyring_secret_service_get_item(keyring, service, username);

  guint listlength = g_list_length(secretlist);
  if (listlength == 0) {
    g_list_free(secretlist);
    error("keyring item not found");

  } else if (listlength > 1) {
    warning("Multiple matching keyring items found, returning first");
  }

  SecretItem *secretitem = g_list_first(secretlist)->data;
  SecretValue *secretvalue = secret_item_get_secret(secretitem);

  if (!secretvalue) {
    g_list_free(secretlist);
    error("Cannot get password");
  }

  gsize passlength;
  const gchar *password = secret_value_get(secretvalue, &passlength);
  SEXP result = ScalarString(mkCharLen((const char*) password,
				       (size_t) passlength));
  g_list_free(secretlist);
  return result;
}

SEXP keyring_secret_service_set(SEXP keyring, SEXP service, SEXP username,
				SEXP password) {
  const char* empty = "";
  const char* cservice = CHAR(STRING_ELT(service, 0));
  const char* cusername =
    isNull(username) ? empty : CHAR(STRING_ELT(username, 0));
  const char* cpassword = CHAR(STRING_ELT(password, 0));

  SecretCollection *collection = NULL;
  GHashTable *attributes = NULL;
  GError *err = NULL;

  collection = keyring_secret_service_get_collection(keyring);
  attributes = g_hash_table_new(
    /* hash_func = */ (GHashFunc) g_str_hash,
    /* key_equal_func = */ (GEqualFunc) g_str_equal);

  g_hash_table_insert(attributes, g_strdup("service"), g_strdup(cservice));
  g_hash_table_insert(attributes, g_strdup("username"), g_strdup(cusername));

  SecretValue *value = secret_value_new(cpassword, -1,
					/* content_type = */ "text/plain");

  SecretItem *item = secret_item_create_sync(
    collection,
    keyring_secret_service_schema(),
    attributes,
    /* label = */ cservice,
    value,
    /* flags = */ SECRET_ITEM_CREATE_REPLACE,
    /* cancellable = */ NULL,
    &err);

  if (item) g_object_unref(item);
  keyring_secret_service_handle_status("set", TRUE, err);

  return R_NilValue;
}

SEXP keyring_secret_service_delete(SEXP keyring, SEXP service, SEXP username) {

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

SEXP keyring_secret_service_list(SEXP keyring, SEXP service) {

  const char *cservice = isNull(service) ? NULL : CHAR(STRING_ELT(service, 0));
  const char *errormsg = NULL;

  GList *secretlist = NULL, *iter = NULL;
  guint listlength, i;
  GHashTable *attributes = NULL;
  GError *err = NULL;

  SEXP result = R_NilValue;

  SecretCollection *collection = keyring_secret_service_get_collection(keyring);

  /* If service is not NULL, then we only look for the specified service. */
  attributes = g_hash_table_new(
    /* hash_func = */ (GHashFunc) g_str_hash,
    /* key_equal_func = */ (GEqualFunc) g_str_equal);

  if (cservice) {
    g_hash_table_insert(attributes, g_strdup("service"), g_strdup(cservice));
  }

  secretlist = secret_collection_search_sync(
    /* self = */ collection,
    /* schema = */ keyring_secret_service_schema(),
    /* attributes = */ attributes,
    /* flags = */ SECRET_SEARCH_ALL,
    /* cancellable = */ NULL,
    &err);

  if (err) goto cleanup;

  listlength = g_list_length(secretlist);
  result = PROTECT(allocVector(VECSXP, 2));
  SET_VECTOR_ELT(result, 0, allocVector(STRSXP, listlength));
  SET_VECTOR_ELT(result, 1, allocVector(STRSXP, listlength));
  for (i = 0, iter = g_list_first(secretlist); iter; i++, iter = g_list_next(iter)) {
    SecretItem *secret = iter->data;
    GHashTable *attr = secret_item_get_attributes(secret);
    char *service = g_hash_table_lookup(attr, "service");
    char *username = g_hash_table_lookup(attr, "username");
    SET_STRING_ELT(VECTOR_ELT(result, 0), i, mkChar(service));
    SET_STRING_ELT(VECTOR_ELT(result, 1), i, mkChar(username));
  }

  UNPROTECT(1);

  /* If an error happened, then err is not NULL, and the handler longjumps.
     Otherwise if errormsg is not NULL, then we error out with that. This
     happens for example if the specified keyring is not found. */

 cleanup:
  if (collection) g_object_unref(collection);
  if (secretlist) g_list_free(secretlist);
  if (attributes) g_hash_table_unref(attributes);
  keyring_secret_service_handle_status("list", TRUE, err);
  if (errormsg) error(errormsg);

  return result;
}

#endif // __linux__
