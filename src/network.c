#include <curl/curl.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network.h"

typedef struct {
	const gchar *url;

	FILE *ul;
	size_t ul_size;

	FILE *dl;
	size_t dl_size;

	size_t pos;
	size_t limit;
} RaucTransfer;

gboolean network_init(GError **error)
{
	CURLcode res;

	g_return_val_if_fail(error == FALSE || *error == NULL, FALSE);

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
		if ((xfer->pos + size*nmemb) > xfer->limit)
			return 0;
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
		if (dltotal > (curl_off_t)xfer->limit)
			return 1;
		if (dlnow > (curl_off_t)xfer->limit)
			return 1;
	}

	return 0;
}

static gboolean transfer(RaucTransfer *xfer, GError **error)
{
	CURL *curl = NULL;
	CURLcode r;
	char errbuf[CURL_ERROR_SIZE];
	gboolean res = FALSE;

	curl = curl_easy_init();
	if (curl == NULL)
		goto out;

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
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, xfer);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);

	/* set error buffer empty before perorming a request */
	errbuf[0] = 0;

	r = curl_easy_perform(curl);
	if (r == CURLE_HTTP_RETURNED_ERROR) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "HTTP returned >=400");
		res = FALSE;
		goto out;
	} else if (r != CURLE_OK) {
		size_t len = strlen(errbuf);
		if (len)
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transfer failed: %s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
		else
			g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Transfer failed: %s", curl_easy_strerror(res));
		res = FALSE;
		goto out;
	}
	res = TRUE;

	if (xfer->dl)
		fflush(xfer->dl);

out:
	g_clear_pointer(&curl, curl_easy_cleanup);
	return res;
}

gboolean download_file(const gchar *target, const gchar *url, gsize limit, GError **error)
{
	RaucTransfer xfer = {0};
	gboolean res = FALSE;
	GError *ierror = NULL;

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

gboolean download_file_checksum(const gchar *target, const gchar *url,
		const RaucChecksum *checksum)
{
	g_autofree gchar *tmpname = NULL;
	g_autofree gchar *dir = NULL;
	g_autofree gchar *tmppath = NULL;
	gboolean res = FALSE;

	tmpname = g_strdup_printf(".rauc_%s_%"G_GSIZE_FORMAT, checksum->digest,
			checksum->size);
	dir = g_path_get_dirname(target);
	tmppath = g_build_filename(dir, tmpname, NULL);

	g_unlink(target);
	g_unlink(tmppath);

	if (g_file_test(target, G_FILE_TEST_EXISTS))
		goto out;
	if (g_file_test(tmppath, G_FILE_TEST_EXISTS))
		goto out;

	res = download_file(tmppath, url, checksum->size, NULL);
	if (!res)
		goto out;

	res = verify_checksum(checksum, tmppath, NULL);
	if (!res)
		goto out;

	res = (g_rename(tmppath, target) == 0);
	if (!res)
		goto out;

out:
	return res;
}

gboolean download_mem(GBytes **data, const gchar *url, gsize limit, GError **error)
{
	RaucTransfer xfer = {0};
	gboolean res = FALSE;
	GError *ierror = NULL;
	char *dl_data = NULL;

	xfer.url = url;
	xfer.limit = limit;

	xfer.dl = open_memstream(&dl_data, &xfer.dl_size);
	if (xfer.dl == NULL) {
		g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Failed opening memstream");
		goto out;
	}

	res = transfer(&xfer, &ierror);
	if (!res) {
		g_propagate_error(error, ierror);
		goto out;
	}

	g_clear_pointer(&xfer.dl, fclose);
	*data = g_bytes_new_take(dl_data, xfer.dl_size);
	dl_data = NULL;

out:
	g_clear_pointer(&xfer.dl, fclose);
	g_clear_pointer(&dl_data, free);
	return res;
}
