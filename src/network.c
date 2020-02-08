#include <curl/curl.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network.h"

/* We need to make sure that we can support large bundles. */
G_STATIC_ASSERT(sizeof(curl_off_t) == 8);

typedef struct {
	const gchar *url;

	FILE *dl;

	curl_off_t pos;
	curl_off_t limit;

	gchar *err;
} RaucTransfer;

gboolean network_init(GError **error)
{
	CURLcode res;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	res = curl_global_init(CURL_GLOBAL_ALL);
	if (res != CURLE_OK) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Initializing curl failed: %s", curl_easy_strerror(res));
		return FALSE;
	}

	return TRUE;
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	RaucTransfer *xfer = userdata;
	size_t res;

	/* check transfer limit */
	if (xfer->limit) {
		if ((guint64)(xfer->pos + size*nmemb) > (guint64)xfer->limit) {
			xfer->err = g_strdup("Maximum bundle download size exceeded. Download aborted.");
			return 0;
		}
	}

	res = fwrite(ptr, size, nmemb, xfer->dl);
	xfer->pos += size*res;

	return res;
}

static int xfer_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
		curl_off_t ultotal, curl_off_t ulnow)
{
	RaucTransfer *xfer = clientp;

	/* check transfer limit */
	if (xfer->limit) {
		if ((dlnow > xfer->limit)
		    || (dltotal > xfer->limit)) {
			xfer->err = g_strdup("Maximum bundle download size exceeded. Download aborted.");
			return 1;
		}
	}

	return 0;
}

static gboolean transfer(RaucTransfer *xfer, GError **error)
{
	CURL *curl = NULL;
	CURLcode r;
	char errbuf[CURL_ERROR_SIZE];
	gboolean res = FALSE;

	g_return_val_if_fail(xfer, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	curl = curl_easy_init();
	if (curl == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Unable to start libcurl easy session");
		goto out;
	}

	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); /* avoid signals for threading */
	curl_easy_setopt(curl, CURLOPT_URL, xfer->url);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 8L);
	//curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, 1048576L); /* bytes per second */
	//curl_easy_setopt(curl,  CURLOPT_LOW_SPEED_LIMIT, 1024L);
	//curl_easy_setopt(curl,  CURLOPT_LOW_SPEED_TIME, 60L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, xfer);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xfer_cb);
	curl_easy_setopt(curl, CURLOPT_XFERINFODATA, xfer);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, xfer->limit);
	/* decode all supported Accept-Encoding headers */
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

	/* set error buffer empty before performing a request */
	errbuf[0] = 0;

	r = curl_easy_perform(curl);
	if (r == CURLE_HTTP_RETURNED_ERROR) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "HTTP returned >=400");
		goto out;
	} else if (r != CURLE_OK) {
		size_t len = strlen(errbuf);
		if (xfer->err) {
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transfer failed: %s", xfer->err);
			g_clear_pointer(&xfer->err, &g_free);
		} else if (len) {
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transfer failed: %s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
		} else {
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transfer failed: %s", curl_easy_strerror(r));
		}
		goto out;
	}
	res = TRUE;

	if (xfer->dl)
		fflush(xfer->dl);

out:
	g_clear_pointer(&curl, curl_easy_cleanup);
	return res;
}

gboolean download_file(const gchar *target, const gchar *url, goffset limit, GError **error)
{
	RaucTransfer xfer = {0};
	gboolean res = FALSE;
	GError *ierror = NULL;

	g_return_val_if_fail(target, FALSE);
	g_return_val_if_fail(url, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	xfer.url = url;
	xfer.limit = limit;

	/* TODO: resume incomplete downloads */

	xfer.dl = fopen(target, "wbx");
	if (xfer.dl == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed opening target file");
		goto out;
	}

	res = transfer(&xfer, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

out:
	g_clear_pointer(&xfer.dl, fclose);
	return res;
}
