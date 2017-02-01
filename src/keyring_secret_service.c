
#ifdef __linux__

#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

#include <dbus/dbus.h>

#define KEYRING_SS_BUS_NAME   "org.freedesktop.secrets"
#define KEYRING_SS_PREFIX     "org.freedesktop.Secret"
#define KEYRING_SS_COLLECTION "org.freedesktop.Secret.Collection"
#define KEYRING_SS_SERVICE    "org.freedesktop.Secret.Service"

#define KEYRING_SS_PATH            "/org/freedesktop/secrets"
#define KEYRING_DEFAULT_COLLECTION "/org/freedesktop/secrets/aliases/default"
#define KEYRING_SESSION_COLLECTION "/org/freedesktop/secrets/collection/session"

#define KEYRING_DBUS_UNKNOWN_METHOD  "org.freedesktop.DBus.Error.UnknownMethod"
#define KEYRING_DBUS_ACCESS_DENIED   "org.freedesktop.DBus.Error.AccessDenied"
#define KEYRING_DBUS_SERVICE_UNKNOWN "org.freedesktop.DBus.Error.ServiceUnknown"
#define KEYRING_DBUS_EXEC_FAILED     "org.freedesktop.DBus.Error.Spawn.ExecFailed"
#define KEYRING_DBUS_NO_REPLY        "org.freedesktop.DBus.Error.NoReply"
#define KEYRING_DBUS_NOT_SUPPORTED   "org.freedesktop.DBus.Error.NotSupported"
#define KEYRING_DBUS_NO_SUCH_OBJECT  "org.freedesktop.Secret.Error.NoSuchObject"

#define KEYRING_ALGORITHM_PLAIN "plain"
#define KEYRING_ALGORITHM_DH    "dh-ietf1024-sha256-aes128-cbc-pkcs7"

static void keyring_secret_service_handle_status(const char* msg,
						 DBusError* status) {

  if (dbus_error_is_set(status)) {
    fprintf(stderr, "DBusError.name: %s\n", status->name);
    fprintf(stderr, "DBusError.message: %s\n", status->message);
    dbus_error_free(status);
    error("Secret service keyring error: %s, %s", msg, "TODO");
  }
}

SEXP keyring_secret_service_set(SEXP service, SEXP username, SEXP password) {

  /* Structure representing the connection to a bus. */
  DBusConnection* bus = NULL;
  /* The method call message. */
  DBusMessage* msg = NULL;

  DBusError dbus_status;
  dbus_error_init(&dbus_status);

  printf("Connecting to Session D-Bus\n");
  bus = dbus_bus_get(DBUS_BUS_SESSION, &dbus_status);
  keyring_secret_service_handle_status(
    "Failed to open Session bus\n",
    &dbus_status);

  printf("Checking whether the target name exists (" KEYRING_SS_BUS_NAME ")\n");
  if (!dbus_bus_name_has_owner(bus, KEYRING_SS_BUS_NAME, &dbus_status)) {
    fprintf(stderr, "Name has no owner on the bus!\n");
    error("Secret service keyring error: keyring daemon is not running");
  }
  keyring_secret_service_handle_status("check for service", &dbus_status);

  printf("Creating a message object\n");
  msg = dbus_message_new_method_call(
    /* destination = */ KEYRING_SS_BUS_NAME,
    /* object path = */ KEYRING_SS_PATH,
    /* interface   = */ KEYRING_SS_SERVICE,
    /* method      = */ "OpenSession");

  if (msg == NULL) {
    fprintf(stderr, "Ran out of memory when creating a message\n");
    error("Out of memory");
  }

  printf("Appending arguments to the message\n");
  if (!dbus_message_append_args(msg,
				DBUS_TYPE_STRING, KEYRING_ALGORITHM_DH,
                                DBUS_TYPE_UINT32, &iconType,
                                DBUS_TYPE_STRING, &buttonText,
                                DBUS_TYPE_INVALID)) {
    fprintf(stderr, "Ran out of memory while constructing args\n");
    exit(EXIT_FAILURE);
  }

  printf("Adding message to client's send-queue\n");
  /* We could also get a serial number (dbus_uint32_t) for the message
     so that we could correlate responses to sent messages later. In
     our case there won't be a response anyway, so we don't care about
     the serial, so we pass a NULL as the last parameter. */
  if (!dbus_connection_send(bus, msg, NULL)) {
    fprintf(stderr, "Ran out of memory while queueing message\n");
    exit(EXIT_FAILURE);
  }

  printf("Waiting for send-queue to be sent out\n");
  dbus_connection_flush(bus);

  printf("Queue is now empty\n");

  /* Now we could in theory wait for exceptions on the bus, but since
     this is only a simple D-Bus example, we'll skip that. */

  printf("Cleaning up\n");

  /* Free up the allocated message. Most D-Bus objects have internal
     reference count and sharing possibility, so _unref() functions
     are quite common. */
  dbus_message_unref(msg);
  msg = NULL;

  /* Free-up the connection. libdbus attempts to share existing
     connections for the same client, so instead of closing down a
     connection object, it is unreferenced. The D-Bus library will
     keep an internal reference to each shared connection, to
     prevent accidental closing of shared connections before the
     library is finalized. */
  dbus_connection_unref(bus);
  bus = NULL;


  return R_NilValue;
}

#endif // __linux__
