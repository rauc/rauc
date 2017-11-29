#include <config.h>

#include <string.h>
#include <errno.h>
#include <gio/gio.h>

#include "bootchooser.h"
#include "config_file.h"
#include "context.h"
#include "install.h"

#define BAREBOX_STATE_NAME "barebox-state"
#define BAREBOX_STATE_DEFAULT_ATTEMPS	3
#define BAREBOX_STATE_ATTEMPS_PRIMARY	3
#define BAREBOX_STATE_DEFAULT_PRIORITY	10
#define BAREBOX_STATE_PRIORITY_PRIMARY	20
#define UBOOT_FWSETENV_NAME "fw_setenv"
#define UBOOT_FWGETENV_NAME "fw_printenv"

static gboolean bootchooser_order_primay(RaucSlot *slot, GString **value) {
	GString *order = g_string_sized_new(10);
	GList *slots;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(value, FALSE);

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

	*value = order;

	return TRUE;
}

typedef struct {
	guint32 prio;
	guint32 attempts;
} BareboxSlotState;

#define BOOTSTATE_PREFIX "bootstate"

#if 0
static gboolean barebox_state_get(const gchar* bootname, BareboxSlotState *bb_state) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GInputStream *instream;
	GDataInputStream *datainstream;
	gchar* outline;
	guint64 result[2] = {};
	GPtrArray *args = g_ptr_array_new_full(6, g_free);
	
	g_return_val_if_fail(bootname, FALSE);
	g_return_val_if_fail(bb_state, FALSE);

	g_ptr_array_add(args, g_strdup(BAREBOX_STATE_NAME));
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority", bootname));
	g_ptr_array_add(args, g_strdup("-g"));
	g_ptr_array_add(args, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts", bootname));
	g_ptr_array_add(args, NULL);

	sub = g_subprocess_newv((const gchar * const *)args->pdata,
				  G_SUBPROCESS_FLAGS_STDOUT_PIPE, &error);
	if (!sub) {
		g_warning("getting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	instream = g_subprocess_get_stdout_pipe(sub);
	datainstream = g_data_input_stream_new(instream);

	for (int i = 0; i < 2; i++) {
		gchar *endptr = NULL;
		outline = g_data_input_stream_read_line(datainstream, NULL, NULL, NULL);
		if (!outline) {
			g_warning("Failed parsing barebox-state output");
			goto out;
		}

		result[i] = g_ascii_strtoull(outline, &endptr, 10);
		if (result[i] == 0 && outline == endptr) {
			g_warning("Failed to parse value: '%s'", outline);
			res = FALSE;
			goto out;
		} else if (result[i] == G_MAXUINT64 && errno != 0) {
			g_warning("Return value overflow: '%s', error: %d", outline, errno);
			res = FALSE;
			goto out;
		}
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("Getting state failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	bb_state->prio = result[0];
	bb_state->attempts = result[1];

out:
	g_ptr_array_unref(args);
	return res;
}
#endif


/* names: list of gchar, values: list of gint */
static gboolean barebox_state_set(GPtrArray *pairs) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;
	GPtrArray *args = g_ptr_array_new_full(2*pairs->len+2, g_free);

	g_return_val_if_fail(pairs, FALSE);

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
		g_warning("starting " BAREBOX_STATE_NAME " failed: %s", error->message);
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

	g_return_val_if_fail(slot, FALSE);

	if (good) {
		attempts = BAREBOX_STATE_DEFAULT_ATTEMPS;
	} else {
		/* for marking bad, also set priority to 0 */
		attempts = 0;
		g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority=%i",
				slot->bootname, 0));
	}

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
			slot->bootname, attempts));

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
	gboolean res = FALSE;
	GList *slots;

	g_return_val_if_fail(slot, FALSE);

	/* Iterate over class members */
	slots = g_hash_table_get_values(r_context()->config->slots);
	for (GList *l = slots; l != NULL; l = l->next) {
		RaucSlot *s = l->data;
		int prio;

		if (s->sclass != slot->sclass)
			continue;

		if (s == slot) {
			prio = BAREBOX_STATE_PRIORITY_PRIMARY;
		} else {
			prio = BAREBOX_STATE_DEFAULT_PRIORITY;
		}
		g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.priority=%i",
				s->bootname, prio));
	}

	g_ptr_array_add(pairs, g_strdup_printf(BOOTSTATE_PREFIX ".%s.remaining_attempts=%i",
			slot->bootname, BAREBOX_STATE_ATTEMPS_PRIMARY));

	res = barebox_state_set(pairs);
	if (!res) {
		g_warning("failed marking as primary");
		goto out;
	}

	res = TRUE;
out:
	g_ptr_array_unref(pairs);
	return res;
}

static gboolean grub_env_set(GPtrArray *pairs) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(pairs, FALSE);

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

	g_return_val_if_fail(slot, FALSE);

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
	GString *order = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(slot, FALSE);

	res = bootchooser_order_primay(slot, &order);
	if (!res) {
		g_warning("failed to create primary boot order");
		goto out;
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
	if (order)
		g_string_free(order, TRUE);
	g_ptr_array_unref(pairs);
	return res;
}

static gboolean uboot_env_get(const gchar *key, GString **value) {
	GSubprocess *sub;
	GError *error = NULL;
	GBytes *stdout_buf = NULL;
	const char *data;
	gsize offset;
	gsize size;
	gboolean res = FALSE;
	gint ret;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &error,
			       UBOOT_FWGETENV_NAME, key, NULL);
	if (!sub) {
		g_warning("starting " UBOOT_FWGETENV_NAME " failed: %s",
			  error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_communicate(sub, NULL, NULL, &stdout_buf, NULL, &error);
	if (!res) {
		g_warning(UBOOT_FWGETENV_NAME " communication failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_get_if_exited(sub);
	if (!res) {
		g_warning(UBOOT_FWGETENV_NAME " did not exit normally");
		goto out;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_warning(UBOOT_FWGETENV_NAME " failed with exit code: %i", ret);
		res = FALSE;
		goto out;
	}

	/* offset is composed of key + equal sign, e.g. 'BOOT_ORDER=A B R' */
	offset = strlen(key) + 1;
	data = g_bytes_get_data(stdout_buf, &size);
	*value = g_string_new_len(data + offset, size - offset);
	g_strchomp((*value)->str);

out:
	g_bytes_unref(stdout_buf);

	return res;
}

static gboolean uboot_env_set(const gchar *key, const gchar *value) {
	GSubprocess *sub;
	GError *error = NULL;
	gboolean res = FALSE;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value, FALSE);

	sub = g_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &error, UBOOT_FWSETENV_NAME,
			       key, value, NULL);
	if (!sub) {
		g_warning("starting fw_setenv failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

	res = g_subprocess_wait_check(sub, NULL, &error);
	if (!res) {
		g_warning("fw_setenv failed: %s", error->message);
		g_clear_error(&error);
		goto out;
	}

out:
	return res;
}

/* Set slot status values */
static gboolean uboot_set_state(RaucSlot *slot, gboolean good) {
	gboolean res = FALSE;
	gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	res = uboot_env_set(key, good ? "3" : "0");
	if (!res) {
		g_warning("failed marking as %s", good ? "good" : "bad");
		goto out;
	}

out:
	g_free(key);
	return res;
}

/* Set slot as primary boot slot */
static gboolean uboot_set_primary(RaucSlot *slot) {
	GString *order_new = g_string_sized_new(10);
	GString *order_current = NULL;
	gchar **bootnames = NULL;
	gboolean res = FALSE;
	gchar *key = NULL;

	g_return_val_if_fail(slot, FALSE);

	/* Add updated slot as first entry in new boot order */
	g_string_append(order_new, slot->bootname);

	res = uboot_env_get("BOOT_ORDER", &order_current);
	if (!res && !bootchooser_order_primay(slot, &order_current))
		goto out;

	/* Iterate over current boot order */
	bootnames = g_strsplit(order_current->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* Skip updated slot, as it is already at the beginning */
		if (g_strcmp0(*bootname, slot->bootname) == 0)
			continue;

		/* skip empty strings from head or tail */
		if (g_strcmp0(*bootname, "") == 0)
			continue;

		g_string_append_c(order_new, ' ');
		g_string_append(order_new, *bootname);
	}

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	res = uboot_env_set(key, "3");
	if (!res) {
		g_warning("failed marking as good");
		goto out;
	}
	res = uboot_env_set("BOOT_ORDER", order_new->str);
	if (!res) {
		g_warning("failed marking as primary");
		goto out;
	}

out:
	g_string_free(order_current, TRUE);
	if (order_new)
		g_string_free(order_new, TRUE);
	g_strfreev(bootnames);
	g_free(key);
	return res;
}

gboolean r_boot_set_state(RaucSlot *slot, gboolean good) {

	g_return_val_if_fail(slot, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_set_state(slot, good);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		return grub_set_state(slot, good);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		return uboot_set_state(slot, good);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "noop") == 0) {
		g_message("noop bootloader: ignore setting slot %s status to %s", slot->name, good ? "good" : "bad");
		return TRUE;
	}

	g_error("bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
	return FALSE;
}

gboolean r_boot_set_primary(RaucSlot *slot) {

	g_return_val_if_fail(slot, FALSE);

	if (g_strcmp0(r_context()->config->system_bootloader, "barebox") == 0) {
		return barebox_set_primary(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "grub") == 0) {
		return grub_set_primary(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "uboot") == 0) {
		return uboot_set_primary(slot);
	} else if (g_strcmp0(r_context()->config->system_bootloader, "noop") == 0) {
		g_message("noop bootloader: ignore setting slot %s as primary", slot->name);
		return TRUE;
	}

	g_error("bootloader type '%s' not supported yet", r_context()->config->system_bootloader);
	return FALSE;
}

