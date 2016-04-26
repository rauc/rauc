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
static gboolean barebox_state_set(GPtrArray *pairs) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(2*pairs->len+2, g_free);

	g_assert_cmpuint(pairs->len, >, 0);
	
	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	for (guint i = 0; i < pairs->len; i++) {
		g_ptr_array_add(args, g_strdup("-s"));
		g_ptr_array_add(args, g_strdup(pairs->pdata[i]));
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

/* Set slot status values */
static gboolean barebox_set_state(RaucSlot *slot, gboolean good) {
	gboolean res = FALSE;
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	int attempts;

	g_assert_nonnull(slot);

	if (good) {
		attempts = 3;
	} else {
		/* for marking bad, also set priority to 0 */
		attempts = 0;
		g_ptr_array_add(pairs, g_strdup_printf("%s.%s.priority=%i",
				BOOTSTATE_PREFIX, slot->bootname, 0));
	}

	g_ptr_array_add(pairs, g_strdup_printf("%s.%s.remaining_attempts=%i",
			BOOTSTATE_PREFIX, slot->bootname, attempts));

	res = barebox_state_set(pairs);
	if (!res) {
		g_warning("failed marking as %s", good ? "good" : "bad");
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

/* Set slot as primary boot slot */
static gboolean barebox_set_primary(RaucSlot *slot) {
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	int prio1 = 20, prio2 = 10;
	gboolean res = FALSE;
	GList *slots;

	g_assert_nonnull(slot);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		int prio;

		if (s->sclass != slot->sclass)
			continue;

		if (s == slot) {
			prio = prio1;
		} else {
			prio = prio2;
		}
		g_ptr_array_add(pairs, g_strdup_printf("%s.%s.priority=%i",
				BOOTSTATE_PREFIX, s->bootname, prio));
	}

	g_ptr_array_add(pairs, g_strdup_printf("%s.%s.ok=%i",
			BOOTSTATE_PREFIX, slot->bootname, 1));
	g_ptr_array_add(pairs, g_strdup_printf("%s.%s.remaining_attempts=%i",
			BOOTSTATE_PREFIX, slot->bootname, 3));

	res = barebox_state_set(pairs);
	if (!res) {
		g_warning("failed marking as primary");
		goto out;
	}

	res = TRUE;
out:
	return res;
}

static gboolean grub_env_set(GPtrArray *pairs) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;

	g_assert_cmpuint(pairs->len, >, 0);
	g_assert_nonnull(r_context()->config->grubenv_path);

	g_ptr_array_insert(pairs, 0, g_strdup("grub-editenv"));
	g_ptr_array_insert(pairs, 1, g_strdup(r_context()->config->grubenv_path));
	g_ptr_array_insert(pairs, 2, g_strdup("set"));
	g_ptr_array_add(pairs, NULL);

	sub = g_subprocess_newv((const gchar * const *)pairs->pdata,
				  G_SUBPROCESS_FLAGS_NONE, &error);
	if (!sub) {
		g_warning("starting grub-editenv failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("grub-editenv failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:
	g_ptr_array_remove_index(pairs, pairs->len-1);
	g_ptr_array_remove_index(pairs, 2);
	g_ptr_array_remove_index(pairs, 1);
	g_ptr_array_remove_index(pairs, 0);
	return res;
}

/* Set slot status values */
static gboolean grub_set_state(RaucSlot *slot, gboolean good) {
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	gboolean res = FALSE;

	g_assert_nonnull(slot);

	if (good) {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=1", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	} else {
		g_ptr_array_add(pairs, g_strdup_printf("%s_OK=0", slot->bootname));
		g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=0", slot->bootname));
	}

	res = grub_env_set(pairs);
	if (!res) {
		g_warning("failed marking as %s", good ? "good" : "bad");
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

/* Set slot as primary boot slot */
static gboolean grub_set_primary(RaucSlot *slot) {
	GPtrArray *pairs = g_ptr_array_new_full(10, g_free);
	GString *order = g_string_sized_new(10);
	gboolean res = FALSE;
	GList *slots;

	g_assert_nonnull(slot);

	g_string_append(order, slot->bootname);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		if (s == slot)
			continue;
		if (s->sclass != slot->sclass)
			continue;

		g_string_append_c(order, ' ');
		g_string_append(order, s->bootname);
	}

	g_ptr_array_add(pairs, g_strdup_printf("%s_OK=%i", slot->bootname, 1));
	g_ptr_array_add(pairs, g_strdup_printf("%s_TRY=%i", slot->bootname, 0));
	g_ptr_array_add(pairs, g_strdup_printf("ORDER=%s", order->str));

	res = grub_env_set(pairs);
	if (!res) {
		g_warning("failed marking as primary");
		goto out;
	}

	res = TRUE;
out:
	g_string_free(order, TRUE);
	g_ptr_array_unref(pairs);
	return res;
}

gboolean r_boot_set_state(RaucSlot *slot, gboolean good) {
	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_set_state(slot, good);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		return grub_set_state(slot, good);
	}

	g_error("bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
	return FALSE;
}

gboolean r_boot_set_primary(RaucSlot *slot) {
	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_set_primary(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		return grub_set_primary(slot);
	}

	g_error("bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
	return FALSE;
}

