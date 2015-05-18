#include <gio/gio.h>
#include <errno.h>

#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "install.h"

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

/* names: list of gchar, values: list of gint */
static gboolean barebox_state_set_int(GList* names, GList* values) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(10, g_free);

	g_assert_cmpint(g_list_length(names), ==, g_list_length(values));
	
	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	for (GList *n = names, *v = values; n != NULL && v != NULL; n = n->next, v = v->next) {
		g_ptr_array_add(args, g_strdup("-s"));
		g_ptr_array_add(args, g_strdup_printf("%s=%i", (gchar*)n->data, *(gint*)v->data));
	}
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

/* Sets slots bootstate priority to 0 */
static gboolean barebox_boot_disable(RaucSlot *slot) {
	gboolean res = FALSE;
	GList *names = NULL, *values = NULL;
	int prio = 0;

	g_assert_nonnull(slot);

	names = g_list_append(names, g_strdup_printf("%s.%s.priority", BOOTSTATE_PREFIX, slot->bootname));
	values = g_list_append(values, &prio);
	res = TRUE;//barebox_state_set_int(names, values);

	if (!res) {
		g_warning("failed marking as bootable");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

/* Set partition as primary boot partiton */
static gboolean barebox_set_primary(RaucSlot *slot) {
	gboolean res = FALSE;
	GList *names = NULL, *values = NULL;
	int prio1 = 20, prio2 = 10, ok = 1;
	GList *slots;

	g_assert_nonnull(slot);

	slots = g_hash_table_get_values(r_context()->config->slots);

	/* Iterate over class members */
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		if (s->sclass != slot->sclass)
			continue;

		names = g_list_append(names, g_strdup_printf("%s.%s.priority", BOOTSTATE_PREFIX, s->bootname));
		if (s == slot) {
			values = g_list_append(values, &prio1);
		} else {
			values = g_list_append(values, &prio2);
		}
	}

	names = g_list_append(names, g_strdup_printf("%s.%s.ok", BOOTSTATE_PREFIX, slot->bootname));
	values = g_list_append(values, &ok);

	res = barebox_state_set_int(names, values);

	if (!res) {
		g_warning("failed marking as bootable");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean grub_boot_disable(RaucSlot *slot) {
	g_print("grub_boot_disable() is not implemented yet\n");
	return TRUE;
}

static gboolean grub_set_primary(RaucSlot *slot) {
	g_print("grub_set_primary() is not implemented yet\n");
	return TRUE;
}

gboolean r_boot_disable(RaucSlot *slot) {
	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_boot_disable(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grup") == 0) {
		return grub_boot_disable(slot);
	}

	g_print("Warning: Your bootloader '%s' is not supported yet\n", r_context()->config->system_bootloader);
	return TRUE;
}

gboolean r_boot_set_primary(RaucSlot *slot) {
	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_set_primary(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grup") == 0) {
		return grub_set_primary(slot);
	}

	g_print("Warning: Your bootloader '%s' is not supported yet\n", r_context()->config->system_bootloader);
	return TRUE;
}

