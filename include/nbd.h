#pragma once

#include <glib.h>
#include <gio/gio.h>

/* FD used to pass the open NBD socket to the server process */
#define RAUC_SOCKET_FD 3

#define R_NBD_ERROR r_nbd_error_quark()
GQuark r_nbd_error_quark(void);

typedef enum {
	R_NBD_ERROR_CONFIGURATION,
	R_NBD_ERROR_STARTUP,
	R_NBD_ERROR_READ,
	R_NBD_ERROR_NO_CONTENT, /* HTTP 204 */
	R_NBD_ERROR_NOT_MODIFIED, /* HTTP 304 */
	R_NBD_ERROR_UNAUTHORIZED, /* HTTP 401 */
	R_NBD_ERROR_NOT_FOUND, /* HTTP 404 */
	R_NBD_ERROR_SHUTDOWN,
} RNBDError;

typedef struct {
	gint sock;
	guint32 index;
	gboolean index_valid;
	gchar *dev;
	guint64 data_size;
} RaucNBDDevice;

typedef struct {
	gint sock; /* client side socket */
	GSubprocess *sproc;

	/* configuration */
	gchar *url;
	gchar *tls_cert; /* local file or PKCS#11 URI */
	gchar *tls_key; /* local file or PKCS#11 URI */
	gchar *tls_ca; /* local file */
	gboolean tls_no_verify;
	GStrv headers; /* array of strings such as 'Foo: bar' */
	GPtrArray *info_headers; /* array of strings such as 'Foo: bar' */

	/* discovered information */
	guint64 data_size; /* bundle size */
	gchar *effective_url; /* url after redirects */
	guint64 current_time; /* date header from server */
	guint64 modified_time; /* last-modified header from server */
	gchar *etag; /* etag received from the server */
} RaucNBDServer;

RaucNBDDevice *r_nbd_new_device(void);
void r_nbd_free_device(RaucNBDDevice *nbd_dev);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucNBDDevice, r_nbd_free_device);

RaucNBDServer *r_nbd_new_server(void);
void r_nbd_free_server(RaucNBDServer *nbd_srv);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucNBDServer, r_nbd_free_server);

/**
 * Configure a NBD device in the kernel using the provided parameters and
 * return the resulting device name in the struct.
 *
 * @param nbd struct with configuration
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean r_nbd_setup_device(RaucNBDDevice *nbd_dev, GError **error);

/**
 * Remove a previously configured NBD device from the kernel.
 *
 * @param nbd struct with configuration
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean r_nbd_remove_device(RaucNBDDevice *nbd_dev, GError **error);

gboolean r_nbd_run_server(gint sock, GError **error);

gboolean r_nbd_start_server(RaucNBDServer *nbd_srv, GError **error);
gboolean r_nbd_stop_server(RaucNBDServer *nbd_srv, GError **error);

gboolean r_nbd_read(gint sock, guint8 *data, size_t size, off_t offset, GError **error);
