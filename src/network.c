#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

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

void network_init(void) {
	curl_global_init(CURL_GLOBAL_ALL);
}

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
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
	    curl_off_t ultotal, curl_off_t ulnow) {
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

static gboolean transfer(RaucTransfer *xfer) {
	CURL *curl = NULL;
	CURLcode r;
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

	r = curl_easy_perform(curl);
	if (r != CURLE_OK) {
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

gboolean download_file(const gchar *target, const gchar *tmpname,
		       const gchar *url, gsize limit) {
	RaucTransfer xfer = {0};
	gboolean res = FALSE;

	xfer.url = url;
	xfer.limit = limit;

	/* TODO: download to temp file first */
	/* TODO: resume incomplete downloads */

	xfer.dl = fopen(target, "wb");
	if (xfer.dl == NULL) {
		goto out;
	}

	res = transfer(&xfer);
	if (!res)
		goto out;

out:
	g_clear_pointer(&xfer.dl, fclose);
	return res;
}

gboolean download_mem(GBytes **data, const gchar *url, gsize limit) {
	RaucTransfer xfer = {0};
	gboolean res = FALSE;
	char *dl_data = NULL;

	xfer.url = url;
	xfer.limit = limit;
	
	xfer.dl = open_memstream(&dl_data, &xfer.dl_size);
	if (xfer.dl == NULL) {
		goto out;
	}

	res = transfer(&xfer);
	if (!res)
		goto out;
	
	g_clear_pointer(&xfer.dl, fclose);
	*data = g_bytes_new_take(dl_data, xfer.dl_size);
	dl_data = NULL;

out:
	g_clear_pointer(&xfer.dl, fclose);
	g_clear_pointer(&dl_data, free);
	return res;
}
