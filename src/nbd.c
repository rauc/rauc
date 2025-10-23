#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "rauc-nbd"

#include <unistd.h>
#include <grp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/sysmacros.h>

#include <glib.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include <linux/nbd-netlink.h>
#include <linux/nbd.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <curl/curl.h>

#include "context.h"
#include "nbd.h"
#include "stats.h"
#include "utils.h"

/* these are only used before passing the socket to the kernel */
#define RAUC_NBD_CMD_CONFIGURE 0x1000
#define RAUC_NBD_HANDLE "\x89\xce\x48\x24\x0c\xe4\x82\xce"

GQuark
r_nbd_error_quark(void)
{
	return g_quark_from_static_string("r-nbd-error-quark");
}

RaucNBDDevice *r_nbd_new_device(void)
{
	RaucNBDDevice *nbd_dev = g_malloc0(sizeof(RaucNBDDevice));

	nbd_dev->sock = -1;

	return nbd_dev;
}

void r_nbd_free_device(RaucNBDDevice *nbd_dev)
{
	g_return_if_fail(nbd_dev);

	if (nbd_dev->index_valid) {
		g_autoptr(GError) ierror = NULL;
		if (!r_nbd_remove_device(nbd_dev, &ierror)) {
			g_message("failed to remove ndb device: %s", ierror->message);
		}
	}

	g_free(nbd_dev);
}

RaucNBDServer *r_nbd_new_server(void)
{
	RaucNBDServer *nbd_srv = g_malloc0(sizeof(RaucNBDServer));

	nbd_srv->sock = -1;

	return nbd_srv;
}

void r_nbd_free_server(RaucNBDServer *nbd_srv)
{
	g_return_if_fail(nbd_srv);

	if (nbd_srv->sproc) {
		g_autoptr(GError) ierror = NULL;
		if (!r_nbd_stop_server(nbd_srv, &ierror)) {
			g_message("failed to stop ndb server: %s", ierror->message);
		}
	}

	g_free(nbd_srv->url);
	g_free(nbd_srv->tls_cert);
	g_free(nbd_srv->tls_key);
	g_free(nbd_srv->tls_ca);
	g_strfreev(nbd_srv->headers);
	g_clear_pointer(&nbd_srv->info_headers, g_ptr_array_unref);
	g_free(nbd_srv->effective_url);
	g_free(nbd_srv->etag);
	g_free(nbd_srv);
}

static int netlink_connect_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	RaucNBDDevice *nbd_dev = arg;
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	int ret;

	ret = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		g_error("invalid response from the kernel");
	if (!msg_attr[NBD_ATTR_INDEX])
		g_error("did not receive index from the kernel");
	nbd_dev->index = nla_get_u32(msg_attr[NBD_ATTR_INDEX]);
	nbd_dev->index_valid = TRUE;

	return NL_OK;
}

static struct nl_sock *netlink_connect(int *driver_id, GError **error)
{
	struct nl_sock *nl = nl_socket_alloc();
	int err;

	if (!nl) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to allocate netlink socket");
		goto out;
	}

	err = genl_connect(nl);
	if (err) {
		nl_socket_free(nl);
		nl = NULL;
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to connect netlink socket: %s", nl_geterror(err));
		goto out;
	}

	*driver_id = genl_ctrl_resolve(nl, "nbd");
	if (*driver_id < 0) {
		nl_close(nl);
		nl_socket_free(nl);
		nl = NULL;
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed to resolve 'nbd' netlink family - BLK_DEV_NBD not enabled in kernel?");
		goto out;
	}

out:
	return nl;
}

gboolean r_nbd_setup_device(RaucNBDDevice *nbd_dev, int *devicefd, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	int driver_id;
	struct nl_sock *nl = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *attr_sockets = NULL;
	struct nlattr *attr_item = NULL;
	g_autofree gchar *device_path = NULL;
	g_auto(filedesc) idevicefd = -1;

	g_return_val_if_fail(nbd_dev != NULL, FALSE);
	g_return_val_if_fail(devicefd != NULL && *devicefd == -1, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert(nbd_dev->data_size % 4096 == 0);

	g_message("configuring nbd device");

	nl = netlink_connect(&driver_id, &ierror);
	if (!nl) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg)
		g_error("failed to allocate netlink message");

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0, NBD_CMD_CONNECT, 0))
		g_error("failed to add generic netlink headers to message");

	/* do not set NBD_ATTR_INDEX to let nbd return a free nbd device index */
	NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, nbd_dev->data_size);
	NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES, 4096);
	NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, 0);
	NLA_PUT_U64(msg, NBD_ATTR_TIMEOUT, 300);

	attr_sockets = nla_nest_start(msg, NBD_ATTR_SOCKETS);
	if (!attr_sockets)
		g_error("failed to allocate nested NBD_ATTR_SOCKETS netlink message");
	attr_item = nla_nest_start(msg, NBD_SOCK_ITEM);
	if (!attr_item)
		g_error("failed to allocate nested NBD_SOCK_ITEM netlink message");
	NLA_PUT_U32(msg, NBD_SOCK_FD, nbd_dev->sock);
	nla_nest_end(msg, attr_item);
	nla_nest_end(msg, attr_sockets);

	nl_socket_modify_cb(nl, NL_CB_VALID, NL_CB_CUSTOM, netlink_connect_cb, nbd_dev);
	if (nl_send_sync(nl, msg) < 0) {
		res = FALSE;
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "netlink send_sync failed");
		goto out;
	}
	if (!nbd_dev->index_valid)
		g_error("failed to create nbd device");

	device_path = g_strdup_printf("/dev/nbd%"G_GUINT32_FORMAT, nbd_dev->index);

	idevicefd = g_open(device_path, O_RDONLY | O_CLOEXEC);
	if (idevicefd < 0) {
		int err = errno;
		g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(err), "failed to open %s: %s", device_path, g_strerror(err));
		res = FALSE;
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg)
		g_error("failed to allocate netlink message");

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0, NBD_CMD_RECONFIGURE, 0))
		g_error("failed to add generic netlink headers to message");

	NLA_PUT_U32(msg, NBD_ATTR_INDEX, nbd_dev->index);
	NLA_PUT_U64(msg, NBD_ATTR_CLIENT_FLAGS, NBD_CFLAG_DISCONNECT_ON_CLOSE);

	nl_socket_modify_cb(nl, NL_CB_VALID, NL_CB_CUSTOM, NULL, NULL);
	if (nl_send_sync(nl, msg) < 0) {
		res = FALSE;
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "netlink send_sync failed");
		goto out;
	}

	g_message("setup done for %s", nbd_dev->dev);

	res = TRUE;
	nbd_dev->dev = g_steal_pointer(&device_path);
	*devicefd = idevicefd;
	idevicefd = -1;
	(void)idevicefd; /* ignore dead store, replace with g_steal_fd when we have glib 2.70 */
	goto out;

	/* This label is used by the NLA_PUT macros. */
nla_put_failure:
	g_error("failed to put netlink attribute");

out:
	if (nl) {
		nl_close(nl);
		nl_socket_free(nl);
	}
	return res;
}

gboolean r_nbd_remove_device(RaucNBDDevice *nbd_dev, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	int driver_id;
	struct nl_sock *nl = NULL;
	struct nl_msg *msg = NULL;

	g_return_val_if_fail(nbd_dev != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!nbd_dev->index_valid)
		return TRUE;

	g_message("Removing nbd device %s", nbd_dev->dev);

	nl = netlink_connect(&driver_id, &ierror);
	if (!nl) {
		res = FALSE;
		g_propagate_error(error, ierror);
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg)
		g_error("failed to allocate netlink message");

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0, NBD_CMD_DISCONNECT, 0))
		g_error("failed to add generic netlink headers to message");

	NLA_PUT_U32(msg, NBD_ATTR_INDEX, nbd_dev->index);

	if (nl_send_sync(nl, msg) < 0) {
		g_message("nbd device is already removed");
	}

	nbd_dev->index_valid = FALSE;
	nbd_dev->index = 0;

	/* maybe reuse the socket to get final statistics/error message? */
	g_close(nbd_dev->sock, NULL);
	nbd_dev->sock = -1;
	g_clear_pointer(&nbd_dev->dev, g_free);

	res = TRUE;
	goto out;

	/* This label is used by the NLA_PUT macros. */
nla_put_failure:
	g_error("failed to put netlink attribute");

out:
	if (nl) {
		nl_close(nl);
		nl_socket_free(nl);
	}
	return res;
}

struct RaucNBDContext {
	gint sock;

	/* configuration */
	guint64 data_size;
	gchar *url;
	gchar *tls_cert; /* local file or PKCS#11 URI */
	gchar *tls_key; /* local file or PKCS#11 URI */
	gchar *tls_ca; /* local file */
	gboolean tls_no_verify;
	struct curl_slist *headers_slist;
	struct curl_slist *initial_headers_slist;

	/* runtime state */
	CURLM *multi;
	gboolean done;

	/* statistics */
	RaucStats *dl_size, *dl_speed, *namelookup, *connect, *starttransfer, *total;
};

struct RaucNBDTransfer {
	struct RaucNBDContext *ctx;

	/* curl */
	CURL *easy;
	char errbuf[CURL_ERROR_SIZE];

	struct nbd_request request;
	struct nbd_reply reply;
	gboolean done;
	guint errors;

	guint8 *buffer;
	curl_off_t buffer_size;
	curl_off_t buffer_pos;

	/* configure request */
	guint64 content_size;
	guint64 current_time; /* date header from server */
	guint64 modified_time; /* last-modified header from server */
	gchar *etag;
};

static void free_transfer(struct RaucNBDTransfer *xfer)
{
	g_clear_pointer(&xfer->buffer, g_free);
	g_clear_pointer(&xfer->etag, g_free);

	g_free(xfer);
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct RaucNBDTransfer *xfer = userdata;
	size_t remaining = 0;

	g_assert_cmpint(size, ==, 1); /* according to the docs, size is always 1 */

	remaining = xfer->buffer_size - xfer->buffer_pos;
	if (remaining < nmemb) {
		return 0;
	}
	memcpy(xfer->buffer + xfer->buffer_pos, ptr, nmemb);
	xfer->buffer_pos += nmemb;

	return nmemb;
}

static size_t header_cb(char *buffer, size_t size, size_t nitems, void *userdata)
{
	struct RaucNBDTransfer *xfer = userdata;

	g_assert_cmpint(size, ==, 1); /* according to the docs, size is always 1 */

	/* make sure we have our own 0-terminated string */
	g_autofree gchar *header = g_strndup(buffer, nitems);
	/* remove trailing whitespace */
	g_strchomp(header);

	g_auto(GStrv) h_pair = g_strsplit(header, ": ", 2);
	if (g_strv_length(h_pair) < 2)
		return nitems;

	g_autofree gchar *h_name = g_ascii_strdown(h_pair[0], -1);
	if (g_str_equal(h_name, "content-range")) {
		g_auto(GStrv) h_elements = NULL;
		g_auto(GStrv) h_range = NULL;
		gchar *endptr = NULL;
		guint64 range_size = 0;

		h_elements = g_strsplit(h_pair[1], " ", 2);
		if (g_strv_length(h_elements) != 2) {
			g_message("failed to parse content-range header");
			return 0;
		}

		h_range = g_strsplit(h_elements[1], "/", 2);
		if (g_strv_length(h_range) != 2) {
			g_message("failed to split content-range value");
			return 0;
		}

		if (!g_str_equal(h_range[0], "0-3") || g_str_equal(h_range[1], "*")) {
			g_message("invalid content-range value");
			return 0;
		}

		errno = 0;
		range_size = g_ascii_strtoull(h_range[1], &endptr, 10);
		if (errno != 0 || endptr[0] != '\0') {
			g_message("failed to parse content-range size");
			return 0;
		}

		xfer->content_size = range_size;

		g_message("nbd server received total size %"G_GUINT64_FORMAT, range_size);
	} else if (g_str_equal(h_name, "date")) {
		time_t date = curl_getdate(h_pair[1], NULL);
		if (date >= 0) {
			xfer->current_time = date;
			g_message("nbd server received HTTP server date %"G_GUINT64_FORMAT, xfer->current_time);
		}
	} else if (g_str_equal(h_name, "last-modified")) {
		time_t date = curl_getdate(h_pair[1], NULL);
		if (date >= 0) {
			xfer->modified_time = date;
			g_message("nbd server received HTTP file date %"G_GUINT64_FORMAT, xfer->modified_time);
		}
	} else if (g_str_equal(h_name, "etag")) {
		r_replace_strdup(&xfer->etag, h_pair[1]);
		g_autofree gchar *escaped = g_strescape(h_pair[1], NULL);
		g_message("nbd server received HTTP ETag: \"%s\"", escaped);
	}

	return nitems;
}

static void prepare_curl(struct RaucNBDTransfer *xfer)
{
	CURLcode code = 0;
	CURLcode tunnel_code = 0;
	g_assert_null(xfer->easy);

	xfer->easy = curl_easy_init();
	if (!xfer->easy)
		g_error("unexpected error from curl_easy_init in %s", G_STRFUNC);

	code |= curl_easy_setopt(xfer->easy, CURLOPT_ERRORBUFFER, xfer->errbuf);

	if (g_getenv("RAUC_CURL_VERBOSE"))
		code |= curl_easy_setopt(xfer->easy, CURLOPT_VERBOSE, 1L);

	code |= curl_easy_setopt(xfer->easy, CURLOPT_URL, xfer->ctx->url);
	if (xfer->ctx->tls_cert)
		code |= curl_easy_setopt(xfer->easy, CURLOPT_SSLCERT, xfer->ctx->tls_cert);
	if (xfer->ctx->tls_key) {
		if (g_str_has_prefix(xfer->ctx->tls_key, "pkcs11:")) {
#if ENABLE_OPENSSL_PKCS11_ENGINE
			code |= curl_easy_setopt(xfer->easy, CURLOPT_SSLKEYTYPE, "ENG");
#else
			code |= curl_easy_setopt(xfer->easy, CURLOPT_SSLKEYTYPE, "PROV");
#endif
		}
		code |= curl_easy_setopt(xfer->easy, CURLOPT_SSLKEY, xfer->ctx->tls_key);
	}
	if (xfer->ctx->tls_ca) {
		code |= curl_easy_setopt(xfer->easy, CURLOPT_CAINFO, xfer->ctx->tls_ca);
		code |= curl_easy_setopt(xfer->easy, CURLOPT_CAPATH, NULL);
	}

	if (xfer->ctx->tls_no_verify)
		code |= curl_easy_setopt(xfer->easy, CURLOPT_SSL_VERIFYPEER, 0L);
	if (xfer->ctx->headers_slist)
		code |= curl_easy_setopt(xfer->easy, CURLOPT_HTTPHEADER, xfer->ctx->headers_slist);

	code |= curl_easy_setopt(xfer->easy, CURLOPT_FOLLOWLOCATION, 1L);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_MAXREDIRS, 8L);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_UNRESTRICTED_AUTH, 1L); /* send authentication to redirect targets as well */

	code |= curl_easy_setopt(xfer->easy, CURLOPT_NOSIGNAL, 1L); /* avoid signals for threading */
	code |= curl_easy_setopt(xfer->easy, CURLOPT_FAILONERROR, 1L);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_NETRC, CURL_NETRC_OPTIONAL);

	/* use a shorter timeout instead of the 5 minute default */
	code |= curl_easy_setopt(xfer->easy, CURLOPT_CONNECTTIMEOUT, 20L);

	/* a proxy may be configured using .netrc */
	tunnel_code = curl_easy_setopt(xfer->easy, CURLOPT_HTTPPROXYTUNNEL, 1L);
	if (tunnel_code == CURLE_UNKNOWN_OPTION) {
		g_debug("no proxy support available in libcurl (failed to set CURLOPT_HTTPPROXYTUNNEL)");
	} else {
		code |= tunnel_code;
	}
	code |= curl_easy_setopt(xfer->easy, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);

	code |= curl_easy_setopt(xfer->easy, CURLOPT_PRIVATE, xfer);

	if (code)
		g_error("unexpected error from curl_easy_setopt in %s", G_STRFUNC);
}

static void collect_curl_stats(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	CURLcode code;
	double time;
	curl_off_t size;

	code = curl_easy_getinfo(xfer->easy, CURLINFO_NAMELOOKUP_TIME, &time);
	if (code == CURLE_OK) {
		//g_message("NAMELOOKUP %.3f", time);
		r_stats_add(ctx->namelookup, time);
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_CONNECT_TIME, &time);
	if (code == CURLE_OK) {
		//g_message("CONNECT %.3f", time);
		r_stats_add(ctx->connect, time);
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_STARTTRANSFER_TIME, &time);
	if (code == CURLE_OK) {
		//g_message("STARTTRANSFER %.3f", time);
		r_stats_add(ctx->starttransfer, time);
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_TOTAL_TIME, &time);
	if (code == CURLE_OK) {
		//g_message("TOTAL %.3f", time);
		r_stats_add(ctx->total, time);
	}
	code = curl_easy_getinfo(xfer->easy, CURLINFO_SIZE_DOWNLOAD_T, &size);
	if (code == CURLE_OK) {
		//g_message("SIZE_DOWNLOAD %ld", size);
		r_stats_add(ctx->dl_size, size);
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_SPEED_DOWNLOAD, &time);
	if (code == CURLE_OK) {
		//g_message("SPEED_DOWNLOAD %.3f", time);
		r_stats_add(ctx->dl_speed, time);
	}
}

static void start_read(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	CURLcode code = 0;
	CURLMcode mcode = 0;
	g_autofree gchar *range = NULL;

	xfer->buffer = g_malloc(xfer->request.len);
	xfer->buffer_size = xfer->request.len;
	xfer->buffer_pos = 0;

	prepare_curl(xfer);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_WRITEFUNCTION, write_cb);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_WRITEDATA, xfer);
	range = g_strdup_printf("%"G_GUINT64_FORMAT "-%"G_GUINT64_FORMAT,
			(guint64)xfer->request.from,
			(guint64)xfer->request.from + xfer->request.len - 1);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_RANGE, range);
	if (code)
		g_error("unexpected error from curl_easy_setopt in %s", G_STRFUNC);

	mcode = curl_multi_add_handle(ctx->multi, xfer->easy);
	if (mcode != CURLM_OK)
		g_error("unexpected error from curl_multi_add_handle in %s", G_STRFUNC);
}

/* Appends GStrv elements to curl_slist (strings are copied).
 * If curl_slist does not exist yet (NULL passed), it will be created.
 * The created list needs to be freed (after usage) by the caller with
 * curl_slist_free_all(). */
static struct curl_slist *gstrv_add_to_slist(struct curl_slist *initial_list, const GStrv strv)
{
	struct curl_slist *slist = NULL;
	struct curl_slist *temp = NULL;

	if (initial_list)
		slist = initial_list;

	for (GStrv str = strv; *str != NULL; str++) {
		temp = curl_slist_append(slist, *str);
		if (temp == NULL) {
			curl_slist_free_all(slist);
			g_error("unexpected error from curl_slist_append in %s (out of memory?)", G_STRFUNC);
			return NULL;
		}
		slist = temp;
	}

	return slist;
}

static void start_configure(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	gboolean res = FALSE;
	CURLcode code = 0;
	CURLMcode mcode = 0;

	/* only read from the client on the first try */
	if (!ctx->url) {
		g_autofree guint8 *data = g_malloc(xfer->request.len);
		g_autoptr(GVariant) v = NULL;
		g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);
		g_auto(GStrv) headers = NULL; /* array of strings such as 'Foo: bar' */
		g_auto(GStrv) info_headers = NULL; /* array of strings such as 'Foo: bar' */

		res = r_read_exact(ctx->sock, (guint8*)data, xfer->request.len, NULL);
		g_assert_true(res);

		v = g_variant_new_from_data(G_VARIANT_TYPE_VARDICT,
				data, xfer->request.len,
				FALSE,
				NULL, NULL);
		g_assert_nonnull(v);
		{
			g_autofree gchar *tmp = g_variant_print(v, TRUE);
			g_message("nbd server received configuration: %s", tmp);
		}

		g_variant_dict_init(&dict, v);
		g_variant_dict_lookup(&dict, "url", "s", &ctx->url);
		g_variant_dict_lookup(&dict, "cert", "s", &ctx->tls_cert);
		g_variant_dict_lookup(&dict, "key", "s", &ctx->tls_key);
		g_variant_dict_lookup(&dict, "ca", "s", &ctx->tls_ca);
		g_variant_dict_lookup(&dict, "no-verify", "b", &ctx->tls_no_verify);
		g_variant_dict_lookup(&dict, "headers", "^as", &headers);
		g_variant_dict_lookup(&dict, "info-headers", "^as", &info_headers);
		g_assert_nonnull(ctx->url);

		if (headers) {
			ctx->headers_slist = gstrv_add_to_slist(NULL, headers);
			ctx->initial_headers_slist = gstrv_add_to_slist(NULL, headers);
		}
		if (info_headers) {
			ctx->initial_headers_slist = gstrv_add_to_slist(ctx->initial_headers_slist, info_headers);
		}
	}

	g_message("nbd server configuring for URL: %s", ctx->url);

	prepare_curl(xfer);
	if (ctx->initial_headers_slist) {
		/* The first request sends the system information */
		code |= curl_easy_setopt(xfer->easy, CURLOPT_HTTPHEADER, ctx->initial_headers_slist);
	}
	code |= curl_easy_setopt(xfer->easy, CURLOPT_USERAGENT, PACKAGE_NAME "/" PACKAGE_VERSION);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_HEADERFUNCTION, header_cb);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_HEADERDATA, xfer);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_WRITEFUNCTION, write_cb);
	code |= curl_easy_setopt(xfer->easy, CURLOPT_WRITEDATA, xfer);
	/* we could try a HEAD request, but prefer to check if range requests work */
	code |= curl_easy_setopt(xfer->easy, CURLOPT_RANGE, "0-3"); /* get the "sqsh" magic */

	if (code)
		g_error("unexpected error from curl_easy_setopt in %s", G_STRFUNC);

	xfer->buffer = g_malloc(4);
	xfer->buffer_size = 4;
	xfer->buffer_pos = 0;

	g_debug("nbd server sending initial range request to HTTP server");

	mcode = curl_multi_add_handle(ctx->multi, xfer->easy);
	if (mcode != CURLM_OK)
		g_error("unexpected error from curl_multi_add_handle in %s", G_STRFUNC);
}

static void start_request(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	switch (xfer->request.type) {
		case NBD_CMD_READ: {
			start_read(ctx, xfer);
			break;
		}
		case NBD_CMD_DISC: {
			g_message("nbd server received disconnect request");
			ctx->done = TRUE;
			free_transfer(xfer); /* not queued via curl_multi_add_handle */
			break;
		}
		case RAUC_NBD_CMD_CONFIGURE: {
			start_configure(ctx, xfer);
			break;
		}
		default: {
			g_error("nbd server received bad request type");
			break;
		}
	}
}

static gboolean finish_read(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	gboolean res = FALSE;

	if (!xfer->done) { /* retry */
		res = TRUE;
		goto out;
	}

	/* If reply is considered error-free so far, check that response_code
	 * is actually 206 */
	if (xfer->reply.error == 0) {
		long response_code = 0;
		CURLcode code = curl_easy_getinfo(xfer->easy, CURLINFO_RESPONSE_CODE, &response_code);
		if (code != CURLE_OK)
			g_error("unexpected error from curl_easy_getinfo in %s", G_STRFUNC);

		if (response_code != 206) {
			g_warning("unexpected HTTP response code %ld from curl_easy_getinfo in %s", response_code, G_STRFUNC);
			xfer->reply.error = GUINT32_TO_BE(5); /* NBD_EIO */
		}
	}

	if (!r_write_exact(ctx->sock, (guint8*)&xfer->reply, sizeof(xfer->reply), NULL))
		g_error("failed to send nbd read reply header");
	if (xfer->reply.error == 0) {
		if (xfer->buffer_size != xfer->buffer_pos)
			g_error("incomplete data received from server");

		if (!r_write_exact(ctx->sock, xfer->buffer, xfer->buffer_size, NULL))
			g_error("failed to send nbd read reply body");
	}

	collect_curl_stats(ctx, xfer);

	res = TRUE;
out:
	g_clear_pointer(&xfer->buffer, g_free);

	return res;
}

static gboolean finish_configure(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	gboolean res = FALSE;
	CURLcode code;
	long response_code = 0;
	long http_version = 0;
	const char *effective_url = NULL;
	g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);
	g_autoptr(GVariant) v = NULL;
	guint32 reply_size;

	/* This can only be called after the client has sent a configure command. */
	g_assert_nonnull(ctx->url);

	if (!xfer->done) { /* retry */
		res = TRUE;
		goto out;
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_RESPONSE_CODE, &response_code);
	if (code != CURLE_OK)
		g_error("unexpected error from curl_easy_getinfo in %s", G_STRFUNC);

	if (response_code != 206) {
		g_autofree gchar *error = NULL;
		switch (response_code) {
			case 0:
				error = g_strdup_printf("server not responding");
				break;
			case 200:
				error = g_strdup_printf("range requests not supported by server");
				break;
			case 204:
				error = g_strdup_printf("no content");
				break;
			case 304:
				error = g_strdup_printf("not modified");
				break;
			default:
				error = g_strdup_printf("unexpected HTTP response code %ld", response_code);
		}
		g_variant_dict_insert(&dict, "error", "s", error);
		g_variant_dict_insert(&dict, "error-http-code", "u", (guint32)response_code);
		res = FALSE;
		goto reply;
	}

	if (xfer->buffer_size != xfer->buffer_pos) {
		g_variant_dict_insert(&dict, "error", "s", "incomplete HTTP response");
		res = FALSE;
		goto reply;
	}

	/* any other error detected by curl */
	if (xfer->reply.error) {
		g_variant_dict_insert(&dict, "error", "s", xfer->errbuf);
		res = FALSE;
		goto reply;
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_EFFECTIVE_URL, &effective_url);
	if (code == CURLE_OK) {
		if (!g_str_equal(ctx->url, effective_url))
			g_message("redirected from %s to %s", ctx->url, effective_url);
		g_free(ctx->url);
		ctx->url = g_strdup(effective_url);
	}

	code = curl_easy_getinfo(xfer->easy, CURLINFO_HTTP_VERSION, &http_version);
	if (code == CURLE_OK) {
		if (http_version == CURL_HTTP_VERSION_1_0 ||
		    http_version == CURL_HTTP_VERSION_1_1)
			g_warning("using HTTP/1 for streaming, expect slow installation; enable HTTP/2 if possible");
	}

	collect_curl_stats(ctx, xfer);

	res = TRUE;

reply:
	/* this reply is not handled by the kernel, so we can always include body */
	if (!r_write_exact(ctx->sock, (guint8*)&xfer->reply, sizeof(xfer->reply), NULL))
		g_error("failed to send nbd config reply header");

	if (ctx->url)
		g_variant_dict_insert(&dict, "url", "s", ctx->url);
	if (xfer->content_size) {
		ctx->data_size = xfer->content_size;
		g_variant_dict_insert(&dict, "size", "t", xfer->content_size);
	}
	if (xfer->current_time)
		g_variant_dict_insert(&dict, "current-time", "t", xfer->current_time);
	if (xfer->modified_time)
		g_variant_dict_insert(&dict, "modified-time", "t", xfer->modified_time);
	if (xfer->etag)
		g_variant_dict_insert(&dict, "etag", "s", xfer->etag);

	v = g_variant_dict_end(&dict);
	reply_size = g_variant_get_size(v);

	if (!r_write_exact(ctx->sock, (guint8*)&reply_size, sizeof(reply_size), NULL))
		g_error("failed to send nbd config reply size");
	if (!r_write_exact(ctx->sock, g_variant_get_data(v), g_variant_get_size(v), NULL))
		g_error("failed to send nbd config reply body");

out:
	g_clear_pointer(&xfer->buffer, g_free);

	return res;
}

static gboolean finish_request(struct RaucNBDContext *ctx, struct RaucNBDTransfer *xfer)
{
	gboolean res = FALSE;

	switch (xfer->request.type) {
		case NBD_CMD_READ: {
			res = finish_read(ctx, xfer);
			break;
		}
		case RAUC_NBD_CMD_CONFIGURE: {
			res = finish_configure(ctx, xfer);
			break;
		}
		default: {
			g_message("bad request type");
			break;
		}
	}

	if (xfer->easy) {
		curl_multi_remove_handle(ctx->multi, xfer->easy);
		curl_easy_cleanup(xfer->easy);
		xfer->easy = NULL;
	}

	return res;
}

gboolean r_nbd_run_server(gint sock, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	struct RaucNBDContext ctx = {0};
	struct curl_waitfd waitfd = {0};

	g_return_val_if_fail(sock >= 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		g_set_error(
				error,
				G_FILE_ERROR, g_file_error_from_errno(errno),
				"failed to enable NO_NEW_PRIVS: %s", strerror(errno));
		return FALSE;
	}

	// let us handle broken pipes explicitly
	signal(SIGPIPE, SIG_IGN);

	g_message("nbd server running as UID %d, GID %d", getuid(), getgid());

	ctx.dl_size = r_stats_new("nbd dl_size");
	ctx.dl_speed = r_stats_new("nbd dl_speed");
	ctx.namelookup = r_stats_new("nbd namelookup");
	ctx.connect = r_stats_new("nbd connect");
	ctx.starttransfer = r_stats_new("nbd starttransfer");
	ctx.total = r_stats_new("nbd total");

	ctx.sock = sock;
	ctx.multi = curl_multi_init();

	waitfd.fd = sock;
	waitfd.events = CURL_WAIT_POLLIN;

	while (!ctx.done) {
		int numfds = 0;
		int still_running = 0;
		CURLMcode mcode = curl_multi_wait(ctx.multi, &waitfd, 1, 1000, &numfds);
		if (mcode != CURLM_OK)
			g_error("unexpected error from curl_multi_wait in %s", G_STRFUNC);

		if ((numfds > 0) && (waitfd.revents & CURL_WAIT_POLLIN)) { /* new event from the client */
			struct RaucNBDTransfer *xfer = g_malloc0(sizeof(struct RaucNBDTransfer));
			xfer->ctx = &ctx;

			res = r_read_exact(sock, (guint8*)&xfer->request, sizeof(xfer->request), &ierror);
			if (!res) {
				if (!ierror) { /* disconnected */
					ctx.done = TRUE;
					break;
				} else {
					g_propagate_prefixed_error(
							error,
							ierror,
							"failed to read request from client: ");
					res = FALSE;
					goto out;
				}
			}

			g_assert(xfer->request.magic == GUINT32_TO_BE(NBD_REQUEST_MAGIC));
			xfer->request.type = GUINT32_FROM_BE(xfer->request.type);
			xfer->request.from = GUINT64_FROM_BE(xfer->request.from);
			xfer->request.len = GUINT32_FROM_BE(xfer->request.len);
			//g_message("type 0x%x: from 0x%llx+0x%x", xfer->request.type, xfer->request.from, xfer->request.len);

			xfer->reply.magic = GUINT32_TO_BE(NBD_REPLY_MAGIC);
			memcpy(xfer->reply.handle, xfer->request.handle, sizeof(xfer->reply.handle));

			start_request(&ctx, xfer);
		}

		mcode = curl_multi_perform(ctx.multi, &still_running);
		g_assert(mcode == CURLM_OK);

		while (1) {
			CURLcode code = 0;
			long response_code = 0;
			int msgs_in_queue = 0;
			struct RaucNBDTransfer *xfer = NULL;
			struct CURLMsg *msg = curl_multi_info_read(ctx.multi, &msgs_in_queue);
			if (!msg)
				break;

			if (msg->msg != CURLMSG_DONE) {
				g_message("still running");
				continue;
			}

			code = curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &xfer);
			g_assert(code == CURLE_OK);

			code = curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &response_code);
			if (code != CURLE_OK)
				g_error("unexpected error from curl_easy_getinfo in %s", G_STRFUNC);

			if (msg->data.result == CURLE_OK) {
				g_debug("request done");
				xfer->reply.error = 0;
				xfer->done = TRUE;
			} else if (response_code == 404) {
				g_message("request failed (not found)");
				xfer->reply.error = GUINT32_TO_BE(5); /* NBD_EIO */
				xfer->done = TRUE;
			} else if (xfer->errors >= 5) {
				g_message("request failed (no more retries)");
				xfer->reply.error = GUINT32_TO_BE(5); /* NBD_EIO */
				xfer->done = TRUE;
			} else {
				xfer->errors++;
				g_message("request failed: %s (retrying %d/5)", xfer->errbuf, xfer->errors);
			}

			res = finish_request(&ctx, xfer);
			if (!res) {
				g_set_error(
						error,
						R_NBD_ERROR, R_NBD_ERROR_SHUTDOWN,
						"finish_request failed, shutting down");
				free_transfer(xfer);
				goto out;
			}

			if (xfer->done) {
				free_transfer(xfer);
			} else {
				/* retry */
				sleep(1);
				start_request(&ctx, xfer);
			}
		}
	}

	res = TRUE;
out:
	r_stats_show(ctx.dl_size, NULL);
	r_stats_show(ctx.dl_speed, NULL);
	r_stats_show(ctx.namelookup, NULL);
	r_stats_show(ctx.connect, NULL);
	r_stats_show(ctx.starttransfer, NULL);
	r_stats_show(ctx.total, NULL);

	if (ctx.data_size) {
		double percent_dl = ctx.dl_size->sum * 100.0 / (double)ctx.data_size;
		g_message("downloaded %.1f%% of the full bundle", percent_dl);
	}

	g_clear_pointer(&ctx.url, g_free);
	g_clear_pointer(&ctx.tls_cert, g_free);
	g_clear_pointer(&ctx.tls_key, g_free);
	g_clear_pointer(&ctx.tls_ca, g_free);
	g_clear_pointer(&ctx.dl_size, r_stats_free);
	g_clear_pointer(&ctx.dl_speed, r_stats_free);
	g_clear_pointer(&ctx.namelookup, r_stats_free);
	g_clear_pointer(&ctx.connect, r_stats_free);
	g_clear_pointer(&ctx.starttransfer, r_stats_free);
	g_clear_pointer(&ctx.total, r_stats_free);
	curl_multi_cleanup(ctx.multi);
	g_clear_pointer(&ctx.headers_slist, curl_slist_free_all);
	g_clear_pointer(&ctx.initial_headers_slist, curl_slist_free_all);
	g_message("nbd server exiting");
	return res;
}

/* for development */
G_GNUC_UNUSED
static gpointer nbd_server_thread(gpointer data)
{
	g_autofree gint *sockp = data;
	g_message("started thread %d", *sockp);
	r_nbd_run_server(*sockp, NULL);
	return NULL;
}

static gboolean nbd_configure(RaucNBDServer *nbd_srv, GError **error)
{
	struct nbd_request request = {0};
	struct nbd_reply reply = {0};
	guint32 reply_size = 0;
	g_autofree guint8 *reply_data = NULL;
	g_autofree guint8 *reply_error = NULL;
	g_autoptr(GVariant) v = NULL;
	g_auto(GVariantDict) dict = G_VARIANT_DICT_INIT(NULL);

	g_return_val_if_fail(nbd_srv != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* send config request */
	g_variant_dict_insert(&dict, "url", "s", nbd_srv->url);
	if (nbd_srv->tls_cert)
		g_variant_dict_insert(&dict, "cert", "s", nbd_srv->tls_cert);
	if (nbd_srv->tls_key)
		g_variant_dict_insert(&dict, "key", "s", nbd_srv->tls_key);
	if (nbd_srv->tls_ca)
		g_variant_dict_insert(&dict, "ca", "s", nbd_srv->tls_ca);
	if (nbd_srv->tls_no_verify)
		g_variant_dict_insert(&dict, "no-verify", "b", nbd_srv->tls_no_verify);
	if (nbd_srv->headers)
		g_variant_dict_insert(&dict, "headers", "^as", nbd_srv->headers);
	if (nbd_srv->info_headers)
		g_variant_dict_insert(&dict, "info-headers", "@as",
				g_variant_new_strv((const gchar **)nbd_srv->info_headers->pdata, nbd_srv->info_headers->len));
	v = g_variant_dict_end(&dict);
	{
		g_autofree gchar *tmp = g_variant_print(v, TRUE);
		g_message("sending config request to nbd server: %s", tmp);
	}

	request.magic = GUINT32_TO_BE(NBD_REQUEST_MAGIC);
	request.type = GUINT32_TO_BE(RAUC_NBD_CMD_CONFIGURE);
	request.len = GUINT32_TO_BE(g_variant_get_size(v));
	memcpy(request.handle, RAUC_NBD_HANDLE, sizeof(request.handle));

	if (!r_write_exact(nbd_srv->sock, (guint8*)&request, sizeof(request), NULL))
		g_error("failed to send nbd config request header");
	if (!r_write_exact(nbd_srv->sock, g_variant_get_data(v), g_variant_get_size(v), NULL))
		g_error("failed to send nbd config request body");
	g_clear_pointer(&v, g_variant_unref);

	/* receive config reply */
	if (!r_read_exact(nbd_srv->sock, (guint8*)&reply, sizeof(reply), NULL))
		g_error("failed to recv nbd config reply header");

	if (reply.magic != GUINT32_TO_BE(NBD_REPLY_MAGIC))
		g_error("invalid nbd reply magic");
	if (memcmp(reply.handle, RAUC_NBD_HANDLE, sizeof(reply.handle)) != 0)
		g_error("invalid nbd reply handle");
	/* reply.error is not relevant here, as we have a reply body in any case */

	if (!r_read_exact(nbd_srv->sock, (guint8*)&reply_size, sizeof(reply_size), NULL))
		g_error("failed to recv nbd config reply size");
	reply_data = g_malloc(reply_size);
	if (!r_read_exact(nbd_srv->sock, reply_data, reply_size, NULL))
		g_error("failed to recv nbd config reply body");

	v = g_variant_new_from_data(G_VARIANT_TYPE_VARDICT,
			reply_data, reply_size,
			FALSE,
			NULL, NULL);
	if (!v)
		g_error("failed to deserialize nbd config reply");

	g_variant_dict_init(&dict, v);

	g_variant_dict_lookup(&dict, "error", "s", &reply_error);
	if (reply_error) {
		guint32 http_code = 0;
		g_variant_dict_lookup(&dict, "error-http-code", "u", &http_code);
		g_message("received HTTP response code %"G_GUINT32_FORMAT, http_code);
		if (http_code == 204) {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_NO_CONTENT,
					"no content: %s", reply_error);
		} else if (http_code == 304) {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_NOT_MODIFIED,
					"not modified: %s", reply_error);
		} else if (http_code == 401) {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_UNAUTHORIZED,
					"unauthorized: %s", reply_error);
		} else if (http_code == 404) {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_NOT_FOUND,
					"not found: %s", reply_error);
		} else {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_CONFIGURATION,
					"failed to configure streaming: %s", reply_error);
		}
		return FALSE;
	}

	g_variant_dict_lookup(&dict, "url", "s", &nbd_srv->effective_url);

	g_variant_dict_lookup(&dict, "size", "t", &nbd_srv->data_size);
	if (!nbd_srv->data_size) {
		g_set_error(error, R_NBD_ERROR, R_NBD_ERROR_CONFIGURATION, "server did not send bundle size");
		return FALSE;
	}
	g_autofree gchar* formatted_size = g_format_size_full(nbd_srv->data_size, G_FORMAT_SIZE_LONG_FORMAT);
	g_message("received HTTP server info: total size %s", formatted_size);

	g_variant_dict_lookup(&dict, "current-time", "t", &nbd_srv->current_time);
	if (nbd_srv->current_time) {
		g_autoptr(GDateTime) datetime = g_date_time_new_from_unix_utc(nbd_srv->current_time);
		g_autofree gchar *formatted_date = g_date_time_format(datetime, "%Y-%m-%d %H:%M:%S");
		g_message("received HTTP server info: current time %s (%"G_GUINT64_FORMAT ")", formatted_date, nbd_srv->current_time);
	}
	g_variant_dict_lookup(&dict, "modified-time", "t", &nbd_srv->modified_time);
	if (nbd_srv->modified_time) {
		g_autoptr(GDateTime) datetime = g_date_time_new_from_unix_utc(nbd_srv->modified_time);
		g_autofree gchar *formatted_date = g_date_time_format(datetime, "%Y-%m-%d %H:%M:%S");
		g_message("received HTTP server info: modified time %s (%"G_GUINT64_FORMAT ")", formatted_date, nbd_srv->modified_time);
	}
	g_variant_dict_lookup(&dict, "etag", "s", &nbd_srv->etag);

	return TRUE;
}

typedef struct {
	uid_t uid;
	gid_t gid;
	gid_t *groups;
	int ngroups;
} child_setup_args;

static void clear_child_setup_args(child_setup_args *child_args)
{
	g_clear_pointer(&child_args->groups, g_free);
}
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(child_setup_args, clear_child_setup_args);

static void nbd_server_child_setup(gpointer user_data)
{
	/* see signal-safety(7) for functions which can be used here */
	child_setup_args *args = user_data;

	if (args->groups) {
		if (setgroups(args->ngroups, args->groups) == -1) {
			const char *msg = "setgroups failed\n";
			write(STDOUT_FILENO, msg, strlen(msg));
			exit(1);
		}
	}
	if (args->gid) {
		if (setgid(args->gid) == -1) {
			const char *msg = "setgid failed\n";
			write(STDOUT_FILENO, msg, strlen(msg));
			exit(1);
		}
	}
	if (args->uid) {
		if (setuid(args->uid) == -1) {
			const char *msg = "setuid failed\n";
			write(STDOUT_FILENO, msg, strlen(msg));
			exit(1);
		}
	}
}

static gboolean nbd_server_child_prepare(child_setup_args *args, GError **error)
{
	const gchar *user = NULL;
	struct passwd passwd = {0};
	struct passwd *result = NULL;
	g_autofree gchar *buf = NULL;
	g_autofree gid_t *groups = NULL;
	long bufsize;
	int err;
	int ngroups;

	g_return_val_if_fail(args != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* If we run as non-root (e.g. for 'rauc info'),
	 * there is no need to drop privileges */
	if (getuid() != 0 && getgid() != 0)
		return TRUE;

	user = r_context()->config->streaming_sandbox_user;
	if (user == NULL)
		user = STREAMING_USER;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = 16384;
	buf = g_malloc0(bufsize);

	err = getpwnam_r(user, &passwd, buf, bufsize, &result);
	if (result == NULL) {
		if (err == 0) {
			g_set_error(
					error,
					R_NBD_ERROR, R_NBD_ERROR_STARTUP,
					"user %s not found in user database", user);
			return FALSE;
		} else {
			g_set_error(
					error,
					G_IO_ERROR, g_io_error_from_errno(err),
					"failed to get user %s from database: %s", user, g_strerror(err));
			return FALSE;
		}
	}

	ngroups = 0;
	/* getgrouplist always fail (returns -1), but still sets ngroups to the
	 * number of wanted groups. */
	getgrouplist(user, result->pw_gid, NULL, &ngroups);
	groups = g_malloc0(ngroups * sizeof(*groups));
	args->ngroups = ngroups;

	err = getgrouplist(user, result->pw_gid, groups, &args->ngroups);
	/* Something very weird happened if the number of groups now is different
	 * than the expected number from before. */
	if (err < 0 || args->ngroups != ngroups) {
		g_set_error(
				error,
				R_NBD_ERROR, R_NBD_ERROR_STARTUP,
				"cannot get groups for user %s", user);
		return FALSE;
	}

	args->uid = result->pw_uid;
	args->gid = result->pw_gid;
	args->groups = g_steal_pointer(&groups);

	return TRUE;
}

gboolean r_nbd_start_server(RaucNBDServer *nbd_srv, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;
	gint sockets[2] = {-1, -1};

	g_return_val_if_fail(nbd_srv != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_message("starting the nbd server");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		g_set_error(
				error,
				G_IO_ERROR, g_io_error_from_errno(errno),
				"failed to create unix socket pair: %s",
				g_strerror(errno));
		res = FALSE;
		goto out;
	}

	if (1) { /* subprocess */
		g_auto(child_setup_args) child_args = {0};
		g_autofree gchar *executable = NULL;
		g_autoptr(GSubprocessLauncher) launcher = NULL;
		g_autoptr(GPtrArray) args = g_ptr_array_new_full(3, g_free);

		if (!nbd_server_child_prepare(&child_args, &ierror)) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to prepare streaming subprocess: ");
			res = FALSE;
			goto out;
		}

		/* allow overriding the path for testing */
		executable = g_strdup(g_getenv("RAUC_TEST_NBD_SERVER"));
		if (!executable)
			executable = g_strdup("/proc/self/exe");
		g_ptr_array_add(args, g_steal_pointer(&executable));
		g_ptr_array_add(args, NULL);

		launcher = g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_NONE);
		g_subprocess_launcher_set_child_setup(launcher, nbd_server_child_setup, &child_args, NULL);
		g_subprocess_launcher_setenv(launcher, "RAUC_NBD_SERVER", "", TRUE);
		g_subprocess_launcher_take_fd(launcher, sockets[0], RAUC_SOCKET_FD);
		sockets[0] = -1; /* GSubprocessLauncher takes ownership */

		nbd_srv->sproc = r_subprocess_launcher_spawnv(launcher, args, &ierror);
		if (nbd_srv->sproc == NULL) {
			g_propagate_prefixed_error(
					error,
					ierror,
					"failed to start streaming subprocess: ");
			res = FALSE;
			goto out;
		}
	} else { /* thread for testing */
		gint *sockp = g_malloc(sizeof(gint));
		*sockp = sockets[0];
		g_thread_new("nbd", nbd_server_thread, sockp);
	}

	nbd_srv->sock = sockets[1];
	sockets[1] = -1; /* RaucNBDServer takes ownership */

	if (!nbd_configure(nbd_srv, &ierror)) {
		g_propagate_error(error, ierror);
		res = FALSE;
		goto out;
	}

	g_message("the nbd server was started");

	res = TRUE;

out:
	if (sockets[0] >= 0)
		g_close(sockets[0], NULL);
	if (sockets[1] >= 0)
		g_close(sockets[1], NULL);
	return res;
}

gboolean r_nbd_stop_server(RaucNBDServer *nbd_srv, GError **error)
{
	GError *ierror = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(nbd_srv != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!nbd_srv->sproc)
		return TRUE;

	g_message("stopping the nbd server");

	if (nbd_srv->sock >= 0) {
		struct nbd_request request = {0};

		/* If socket is still active, manually invoke NBD_CMD_DISC
		 * first, to trigger a graceful shutdown of the NBD server. */
		request.magic = GUINT32_TO_BE(NBD_REQUEST_MAGIC);
		request.type = GUINT32_TO_BE(NBD_CMD_DISC);
		request.len = 0;
		if (!r_write_exact(nbd_srv->sock, (guint8*)&request, sizeof(request), &ierror)) {
			g_message("failed to send nbd disconnect request, closing socket: %s", ierror->message);
			g_clear_error(&ierror);
		}

		g_close(nbd_srv->sock, NULL);
		nbd_srv->sock = -1;
	}

	res = g_subprocess_wait_check(nbd_srv->sproc, NULL, &ierror);
	if (!res) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"failed to stop streaming subprocess: ");
		goto out;
	}

	g_message("the nbd server was stopped");

out:
	g_clear_object(&nbd_srv->sproc);
	return res;
}

gboolean r_nbd_read(gint sock, guint8 *data, size_t size, off_t offset, GError **error)
{
	struct nbd_request request = {0};
	struct nbd_reply reply = {0};

	g_return_val_if_fail(sock >= 0, FALSE);
	g_return_val_if_fail(data, FALSE);
	g_return_val_if_fail(size > 0, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	request.magic = GUINT32_TO_BE(NBD_REQUEST_MAGIC);
	request.type = GUINT32_TO_BE(NBD_CMD_READ);
	request.from = GUINT64_TO_BE(offset);
	request.len = GUINT32_TO_BE(size);
	memcpy(request.handle, RAUC_NBD_HANDLE, sizeof(request.handle));

	if (!r_write_exact(sock, (guint8*)&request, sizeof(request), NULL))
		g_error("failed to send nbd read request header");
	if (!r_read_exact(sock, (guint8*)&reply, sizeof(reply), NULL))
		g_error("failed to receive nbd read reply header");

	if (reply.magic != GUINT32_TO_BE(NBD_REPLY_MAGIC))
		g_error("invalid nbd reply magic");
	if (memcmp(reply.handle, RAUC_NBD_HANDLE, sizeof(reply.handle)) != 0)
		g_error("invalid nbd reply handle");
	if (reply.error != GUINT32_TO_BE(0)) {
		g_set_error(
				error,
				R_NBD_ERROR, R_NBD_ERROR_READ,
				"failed to read data from remote server");
		return FALSE;
	}

	if (!r_read_exact(sock, data, size, NULL))
		g_error("failed to receive nbd read reply body");

	return TRUE;
}
