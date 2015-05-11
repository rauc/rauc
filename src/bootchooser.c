#include <gio/gio.h>
#include <errno.h>

#include "bootchooser.h"
#include "config_file.h"

#define BAREBOX_STATE_NAME "barebox-state"

#if 0
static gboolean barebox_state_get_int(const gchar* name, int *value) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;
	guint64 result = 0;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);
	
	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup(name));
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
				  G_SUBPROCESS_FLAGS_NONE, &error);
	if (!sub) {
		g_warning("getting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(sub);
	datainstream = g_data_input_stream_new(instream);

	outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
	if (!outline) {
		g_warning("failed reading state");
		goto out;
	}


	result = g_ascii_strtoull(outline, NULL, 10);
	if (errno != 0) {
		g_warning("Invalid return value: '%s'\n", outline);
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("getting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:
	g_ptr_array_unref(args);
	*value = result;
	return res;
}
#endif

#define BOOTSTATE_PREFIX "bootstate"

static gboolean barebox_state_set_int(const gchar* name, int value) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);
	
	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	g_ptr_array_add(args, g_strdup("-s"));
	g_ptr_array_add(args, g_strdup_printf("%s=%i", name, value));
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
				  G_SUBPROCESS_FLAGS_NONE, &error);
	if (!sub) {
		g_warning("getting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("setting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:
	g_ptr_array_unref(args);
	return res;
}

gboolean r_boot_mark_bootable(RaucSlot *slot, gboolean bootable) {
	gboolean res = FALSE;
	gchar* varname = NULL;

	g_assert_nonnull(slot);

	varname = g_strdup_printf("%s.%s.priority", BOOTSTATE_PREFIX, slot->bootname);
	res = barebox_state_set_int(varname, bootable ? 30 : 0);

	if (!res) {
		g_warning("failed marking as bootable");
		goto out;
	}

	res = TRUE;
out:
	g_clear_pointer(&varname, g_free);
	return res;
}
