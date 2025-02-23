#include "uboot.h"
#include "bootchooser.h"
#include "context.h"
#include "utils.h"

#define UBOOT_FWSETENV_NAME "fw_setenv"
#define UBOOT_FWPRINTENV_NAME "fw_printenv"
#define UBOOT_DEFAULT_ATTEMPTS  3
#define UBOOT_ATTEMPTS_PRIMARY  3

static gboolean uboot_env_get(const gchar *key, GString **value, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;
	g_autoptr(GBytes) stdout_bytes = NULL;
	const char *data;
	gsize offset;
	gsize size;
	gint ret;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value && *value == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = r_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE, &ierror,
			UBOOT_FWPRINTENV_NAME, key, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " UBOOT_FWPRINTENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_communicate(sub, NULL, NULL, &stdout_bytes, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " UBOOT_FWPRINTENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_get_if_exited(sub)) {
		g_set_error_literal(
				error,
				G_SPAWN_ERROR,
				G_SPAWN_ERROR_FAILED,
				UBOOT_FWPRINTENV_NAME " did not exit normally");
		return FALSE;
	}

	ret = g_subprocess_get_exit_status(sub);
	if (ret != 0) {
		g_set_error(
				error,
				G_SPAWN_EXIT_ERROR,
				ret,
				UBOOT_FWPRINTENV_NAME " failed with exit code: %i", ret);
		return FALSE;
	}

	/* offset is composed of key + equal sign, e.g. 'BOOT_ORDER=A B R' */
	offset = strlen(key) + 1;
	data = g_bytes_get_data(stdout_bytes, &size);
	*value = g_string_new_len(data + offset, size - offset);
	g_strchomp((*value)->str);

	return TRUE;
}

static gboolean uboot_env_set(const gchar *key, const gchar *value, GError **error)
{
	g_autoptr(GSubprocess) sub = NULL;
	GError *ierror = NULL;

	g_return_val_if_fail(key, FALSE);
	g_return_val_if_fail(value, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	sub = r_subprocess_new(G_SUBPROCESS_FLAGS_NONE, &ierror, UBOOT_FWSETENV_NAME,
			key, value, NULL);
	if (!sub) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to start " UBOOT_FWSETENV_NAME ": ");
		return FALSE;
	}

	if (!g_subprocess_wait_check(sub, NULL, &ierror)) {
		g_propagate_prefixed_error(
				error,
				ierror,
				"Failed to run " UBOOT_FWSETENV_NAME ": ");
		return FALSE;
	}

	return TRUE;
}

/* We assume bootstate to be good if slot is listed in 'BOOT_ORDER' and its
 * remaining attempts counter is > 0 */
gboolean r_uboot_get_state(RaucSlot *slot, gboolean *good, GError **error)
{
	g_autoptr(GString) order = NULL;
	g_autoptr(GString) attempts = NULL;
	g_auto(GStrv) bootnames = NULL;
	g_autofree gchar *key = NULL;
	GError *ierror = NULL;
	gboolean found = FALSE;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(good, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!uboot_env_get("BOOT_ORDER", &order, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* Scan boot order list for given slot */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		if (g_strcmp0(*bootname, slot->bootname) == 0) {
			found = TRUE;
			break;
		}
	}
	if (!found) {
		*good = FALSE;
		return TRUE;
	}

	/* Check remaining attempts */
	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);
	if (!uboot_env_get(key, &attempts, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	*good = (g_ascii_strtoull(attempts->str, NULL, 16) > 0) ? TRUE : FALSE;

	return TRUE;
}

/* Set slot status values */
gboolean r_uboot_set_state(RaucSlot *slot, gboolean good, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *key = NULL;
	g_autofree gchar *val = NULL;
	gint attempts = 0;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!good) {
		g_autoptr(GString) order_current = NULL;
		g_autoptr(GPtrArray) order_new = NULL;
		g_auto(GStrv) bootnames = NULL;
		g_autofree gchar *order = NULL;

		if (!uboot_env_get("BOOT_ORDER", &order_current, &ierror)) {
			g_message("Unable to obtain BOOT_ORDER: %s", ierror->message);
			g_clear_error(&ierror);
			goto set_left;
		}

		order_new = g_ptr_array_new();
		/* Iterate over current boot order */
		bootnames = g_strsplit(order_current->str, " ", -1);
		for (gchar **bootname = bootnames; *bootname; bootname++) {
			/* Skip selected slot, as we want it to be removed */
			if (g_strcmp0(*bootname, slot->bootname) == 0)
				continue;

			/* Skip empty strings from head or tail */
			if (g_strcmp0(*bootname, "") == 0)
				continue;

			g_ptr_array_add(order_new, *bootname);
		}
		g_ptr_array_add(order_new, NULL);

		order = g_strjoinv(" ", (gchar**) order_new->pdata);
		if (!uboot_env_set("BOOT_ORDER", order, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

set_left:

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	if (good) {
		attempts = r_context()->config->boot_default_attempts;
		if (attempts <= 0)
			attempts = UBOOT_DEFAULT_ATTEMPTS;
	}

	val = g_strdup_printf("%x", attempts);

	if (!uboot_env_set(key, val, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}

/* Get slot marked as primary one */
RaucSlot *r_uboot_get_primary(GError **error)
{
	g_autoptr(GString) order = NULL;
	g_auto(GStrv) bootnames = NULL;
	GError *ierror = NULL;
	RaucSlot *primary = NULL;
	RaucSlot *slot;
	GHashTableIter iter;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!uboot_env_get("BOOT_ORDER", &order, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* Iterate over current boot order */
	bootnames = g_strsplit(order->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* find matching slot entry */
		g_hash_table_iter_init(&iter, r_context()->config->slots);
		while (g_hash_table_iter_next(&iter, NULL, (gpointer*) &slot)) {
			g_autofree gchar *key = NULL;
			g_autoptr(GString) attempts = NULL;

			if (g_strcmp0(*bootname, slot->bootname) != 0)
				continue;

			/* Check that > 0 attempts left */
			key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);
			if (!uboot_env_get(key, &attempts, &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}

			if (g_ascii_strtoull(attempts->str, NULL, 16) <= 0)
				continue;

			primary = slot;
			break;
		}

		if (primary)
			break;
	}

	if (!primary) {
		g_set_error_literal(
				error,
				R_BOOTCHOOSER_ERROR,
				R_BOOTCHOOSER_ERROR_PARSE_FAILED,
				"Unable to find primary boot slot");
	}

	return primary;
}

/* Set slot as primary boot slot */
gboolean r_uboot_set_primary(RaucSlot *slot, GError **error)
{
	g_autoptr(GString) order_new = NULL;
	g_autoptr(GString) order_current = NULL;
	g_auto(GStrv) bootnames = NULL;
	GError *ierror = NULL;
	g_autofree gchar *key = NULL;
	g_autofree gchar *val = NULL;
	gint attempts;

	g_return_val_if_fail(slot, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Add updated slot as first entry in new boot order */
	order_new = g_string_new(slot->bootname);

	if (!uboot_env_get("BOOT_ORDER", &order_current, &ierror)) {
		g_message("Unable to obtain BOOT_ORDER (%s), using defaults", ierror->message);
		g_clear_error(&ierror);

		order_current = r_bootchooser_order_primary(slot);
	}

	/* Iterate over current boot order */
	bootnames = g_strsplit(order_current->str, " ", -1);
	for (gchar **bootname = bootnames; *bootname; bootname++) {
		/* Skip updated slot, as it is already at the beginning */
		if (g_strcmp0(*bootname, slot->bootname) == 0)
			continue;

		/* Skip empty strings from head or tail */
		if (g_strcmp0(*bootname, "") == 0)
			continue;

		g_string_append_c(order_new, ' ');
		g_string_append(order_new, *bootname);
	}

	key = g_strdup_printf("BOOT_%s_LEFT", slot->bootname);

	attempts = r_context()->config->boot_attempts_primary;
	if (attempts <= 0)
		attempts = UBOOT_ATTEMPTS_PRIMARY;

	val = g_strdup_printf("%x", attempts);

	if (!uboot_env_set(key, val, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (!uboot_env_set("BOOT_ORDER", order_new->str, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return TRUE;
}
