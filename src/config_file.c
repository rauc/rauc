#include <glib.h>
#include <string.h>

#include "artifacts.h"
#include "bootchooser.h"
#include "config.h"
#include "config_file.h"
#include "context.h"
#include "event_log.h"
#include "install.h"
#include "manifest.h"
#include "mount.h"
#include "slot.h"
#include "utils.h"

G_DEFINE_QUARK(r-config-error-quark, r_config_error)
G_DEFINE_QUARK(r-slot-error-quark, r_slot_error)

#define RAUC_SLOT_PREFIX	"slot"

static gboolean fix_grandparent_links(GHashTable *slots, GError **error)
{
	/* Every child slot in a group must refer to the same parent.
	 * Some kind of grandparent relationship makes no sense, but if the
	 * user has accidentally constructed such a configuration we will fix
	 * it up for them here. */
	GHashTableIter iter;
	gpointer value;

	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_hash_table_iter_init(&iter, slots);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		RaucSlot *slot = value;
		RaucSlot *realparent;
		unsigned int steps = 0;
		if (slot->parent == NULL)
			continue; /* not part of a group */
		realparent = slot->parent;
		while (realparent->parent) {
			realparent = realparent->parent;
			steps++;
			if (steps > 100) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_PARENT_LOOP,
						"Slot '%s' has a parent loop!", slot->name);
				return FALSE;
			}
		}
		if (realparent != slot->parent) {
			g_message("Updating slot %s parent link to %s",
					slot->name,
					realparent->name);
			slot->parent = realparent;
		}
	}
	return TRUE;
}

gboolean parse_bundle_formats(guint *mask, const gchar *config, GError **error)
{
	gboolean res = TRUE;
	guint imask = 0;
	g_auto(GStrv) tokens = NULL;
	guint set = FALSE, modify = FALSE;

	g_return_val_if_fail(mask != NULL, FALSE);
	g_return_val_if_fail(config != NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	imask = *mask;
	tokens = g_strsplit(config, " ", -1);

	for (size_t i = 0; tokens[i]; i++) {
		const gchar *token = tokens[i];
		gboolean plus = FALSE, minus = FALSE;
		RManifestBundleFormat format;

		if (!token[0]) /* empty string */
			continue;
		if (token[0] == '-') {
			minus = TRUE;
			token++;
		} else if (token[0] == '+') {
			plus = TRUE;
			token++;
		}

		if (g_strcmp0(token, "plain") == 0) {
			format = R_MANIFEST_FORMAT_PLAIN;
		} else if (g_strcmp0(token, "verity") == 0) {
			format = R_MANIFEST_FORMAT_VERITY;
		} else if (g_strcmp0(token, "crypt") == 0) {
			format = R_MANIFEST_FORMAT_CRYPT;
		} else {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Invalid bundle format '%s'", token);
			res = FALSE;
			goto out;
		}

		if (plus || minus) {
			modify = TRUE;
		} else {
			if (!set)
				imask = 0;
			set = TRUE;
		}

		if (minus)
			imask &= ~(1 << format);
		else
			imask |= 1 << format;
	}

	if (set && modify) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_INVALID_FORMAT,
				"Invalid bundle format configuration '%s', cannot combine fixed value with modification (+/-)", config);
		res = FALSE;
		goto out;
	}

	if (!imask) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_INVALID_FORMAT,
				"Invalid bundle format configuration '%s', no remaining formats", config);
		res = FALSE;
		goto out;
	}

out:
	if (res)
		*mask = imask;
	return res;
}

#define RAUC_LOG_EVENT_CONF_PREFIX "log"

static gboolean r_event_log_parse_config_sections(GKeyFile *key_file, RaucConfig *config, GError **error)
{
	gsize group_count;
	g_auto(GStrv) groups = NULL;
	gint tmp_maxfiles;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	g_assert_null(config->loggers);

	/* parse [log.*] sections */
	groups = g_key_file_get_groups(key_file, &group_count);
	for (gchar **group = groups; *group != NULL; group++) {
		GError *ierror = NULL;
		g_autoptr(REventLogger) logger = NULL;
		const gchar *logger_name;
		g_autofree gchar *log_format = NULL;
		gsize entries;

		if (!g_str_has_prefix(*group, RAUC_LOG_EVENT_CONF_PREFIX "."))
			continue;

		logger_name = *group + strlen(RAUC_LOG_EVENT_CONF_PREFIX ".");

		logger = g_new0(REventLogger, 1);
		logger->name = g_strdup(logger_name);

		/* 'filename' option is currently mandatory for a logger group */
		logger->filename = key_file_consume_string(key_file, *group, "filename", &ierror);
		if (!logger->filename) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		/* relative paths are resolved relative to the data-directory */
		if (!g_path_is_absolute(logger->filename)) {
			gchar *abspath;
			if (!config->data_directory) {
				g_set_error_literal(
						error,
						G_KEY_FILE_ERROR,
						G_KEY_FILE_ERROR_INVALID_VALUE,
						"Relative filename requires data-directory to be set");
				return FALSE;
			}

			abspath = g_build_filename(config->data_directory, logger->filename, NULL);
			g_free(logger->filename);
			logger->filename = abspath;
		}

		log_format = key_file_consume_string(key_file, *group, "format", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			g_clear_pointer(&log_format, g_free);
			log_format = g_strdup("readable");
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		if (g_strcmp0(log_format, "readable") == 0) {
			logger->format = R_EVENT_LOGFMT_READABLE;
		} else if (g_strcmp0(log_format, "short") == 0) {
			logger->format = R_EVENT_LOGFMT_READABLE_SHORT;
		} else if (g_strcmp0(log_format, "json") == 0) {
#if ENABLE_JSON
			logger->format = R_EVENT_LOGFMT_JSON;
#else
			g_set_error(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Invalid log format %s. RAUC is compiled without JSON support", log_format);
			return FALSE;
#endif
		} else if (g_strcmp0(log_format, "json-pretty") == 0) {
#if ENABLE_JSON
			logger->format = R_EVENT_LOGFMT_JSON_PRETTY;
#else
			g_set_error(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Invalid log format %s. RAUC is compiled without JSON support", log_format);
			return FALSE;
#endif
		} else {
			g_set_error(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Unknown log format '%s'", log_format);
			return FALSE;
		}

		logger->events = g_key_file_get_string_list(key_file, *group, "events", &entries, &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			g_assert_null(logger->events);
			logger->events = g_malloc(2 * sizeof(gchar *));
			logger->events[0] = g_strdup("all");
			logger->events[1] = NULL;
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		if (g_strv_length(logger->events) > 1 && g_strv_contains((const gchar * const *) logger->events, "all")) {
			g_set_error(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Event type 'all' cannot be combined");
			return FALSE;
		}
		for (gsize j = 0; j < entries; j++) {
			if (!r_event_log_is_supported_type(logger->events[j])) {
				g_set_error(
						error,
						G_KEY_FILE_ERROR,
						G_KEY_FILE_ERROR_INVALID_VALUE,
						"Unsupported event log type '%s'", logger->events[j]);
				return FALSE;
			}
		}
		g_key_file_remove_key(key_file, *group, "events", NULL);

		logger->maxsize = key_file_consume_binary_suffixed_string(key_file, *group, "max-size", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		tmp_maxfiles = key_file_consume_integer(key_file, *group, "max-files", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			tmp_maxfiles = 10;
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		if (tmp_maxfiles < 1) {
			g_set_error_literal(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Value for 'max-files' must be >= 1");
			return FALSE;
		} else if (tmp_maxfiles > 1000) {
			g_set_error_literal(
					error,
					G_KEY_FILE_ERROR,
					G_KEY_FILE_ERROR_INVALID_VALUE,
					"Value of %d for 'max-files' looks implausible");
			return FALSE;
		}
		logger->maxfiles = (guint) tmp_maxfiles;

		if (!check_remaining_keys(key_file, *group, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}

		g_key_file_remove_group(key_file, *group, NULL);

		/* insert new logger in list */
		config->loggers = g_list_append(config->loggers, g_steal_pointer(&logger));
	}

	return TRUE;
}

static gboolean parse_system_section(const gchar *filename, GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;
	gboolean dtbvariant;
	g_autofree gchar *variant_data = NULL;
	g_autofree gchar *version_data = NULL;
	g_autofree gchar *bundle_formats = NULL;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	c->system_compatible = key_file_consume_string(key_file, "system", "compatible", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_pointer(&c->system_compatible, g_free);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* check optional 'min-bundle-version' key for validity */
	version_data = key_file_consume_string(key_file, "system", "min-bundle-version", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_pointer(&version_data, g_free);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (version_data) {
		if (!r_semver_less_equal("0", version_data, NULL)) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Min version format invalid, expected: Major[.Minor[.Patch]][-pre_release], got: %s",
					version_data);
			return FALSE;
		}
		c->system_min_bundle_version = g_steal_pointer(&version_data);
	}

	c->system_bootloader = key_file_consume_string(key_file, "system", "bootloader", NULL);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_pointer(&c->system_bootloader, g_free);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_strcmp0(c->system_bootloader, "barebox") == 0) {
		c->system_bb_statename = key_file_consume_string(key_file, "system", "barebox-statename", NULL);
		c->system_bb_dtbpath = key_file_consume_string(key_file, "system", "barebox-dtbpath", NULL);
	} else if (g_strcmp0(c->system_bootloader, "grub") == 0) {
		c->grubenv_path = resolve_path_take(filename,
				key_file_consume_string(key_file, "system", "grubenv", NULL));
		if (!c->grubenv_path) {
			g_debug("No grubenv path provided, using /boot/grub/grubenv as default");
			c->grubenv_path = g_strdup("/boot/grub/grubenv");
		}
	} else if (g_strcmp0(c->system_bootloader, "efi") == 0) {
		c->efi_use_bootnext = g_key_file_get_boolean(key_file, "system", "efi-use-bootnext", &ierror);
		if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
			c->efi_use_bootnext = TRUE;
			g_clear_error(&ierror);
		} else if (ierror) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
		g_key_file_remove_key(key_file, "system", "efi-use-bootnext", NULL);
	} else if (g_strcmp0(c->system_bootloader, "custom") == 0) {
		c->custom_bootloader_backend = resolve_path_take(filename,
				key_file_consume_string(key_file, "handlers", "bootloader-custom-backend", NULL));
		if (!c->custom_bootloader_backend) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_BOOTLOADER,
					"No custom bootloader backend defined");
			return FALSE;
		}
	}

	c->boot_default_attempts = key_file_consume_integer(key_file, "system", "boot-attempts", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->boot_default_attempts = 0; /* to indicate 'unset' */
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (c->boot_default_attempts < 0) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_BOOTLOADER,
				"Value for \"boot-attempts\" must not be negative");
		return FALSE;
	}

	c->boot_attempts_primary = key_file_consume_integer(key_file, "system", "boot-attempts-primary", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->boot_attempts_primary = 0; /* to indicate 'unset' */
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (c->boot_attempts_primary < 0) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_BOOTLOADER,
				"Value for \"boot-attempts-primary\" must not be negative");
		return FALSE;
	}
	if (c->boot_default_attempts > 0 || c->boot_attempts_primary > 0) {
		if ((g_strcmp0(c->system_bootloader, "uboot") != 0) && (g_strcmp0(c->system_bootloader, "barebox") != 0)) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_BOOTLOADER,
					"Configuring boot attempts is valid for uboot or barebox only (not for %s)", c->system_bootloader);
			return FALSE;
		}
	}

	c->max_bundle_download_size = g_key_file_get_uint64(key_file, "system", "max-bundle-download-size", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_debug("No value for key \"max-bundle-download-size\" in [system] defined "
				"- using default value of %d bytes.", DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE);
		c->max_bundle_download_size = DEFAULT_MAX_BUNDLE_DOWNLOAD_SIZE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	} else if (ENABLE_STREAMING) {
		g_message("Using max-bundle-download-size with streaming has no effect.");
	}
	if (c->max_bundle_download_size == 0) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_MAX_BUNDLE_DOWNLOAD_SIZE,
				"Invalid value (%" G_GUINT64_FORMAT ") for key \"max-bundle-download-size\" in system config", c->max_bundle_download_size);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "max-bundle-download-size", NULL);

	c->max_bundle_signature_size = g_key_file_get_uint64(key_file, "system", "max-bundle-signature-size", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_debug("No value for key \"max-bundle-signature-size\" in [system] defined "
				"- using default value of %d bytes.", DEFAULT_MAX_BUNDLE_SIGNATURE_SIZE);
		c->max_bundle_signature_size = DEFAULT_MAX_BUNDLE_SIGNATURE_SIZE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (c->max_bundle_signature_size == 0) {
		g_set_error(
				error,
				R_CONFIG_ERROR,
				R_CONFIG_ERROR_MAX_BUNDLE_SIGNATURE_SIZE,
				"Invalid value (%" G_GUINT64_FORMAT ") for key \"max-bundle-signature-size\" in system config", c->max_bundle_signature_size);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "max-bundle-signature-size", NULL);

	c->mount_prefix = key_file_consume_string(key_file, "system", "mountprefix", NULL);
	if (!c->mount_prefix) {
		g_debug("No mount prefix provided, using /mnt/rauc/ as default");
		c->mount_prefix = g_strdup("/mnt/rauc/");
	}

	c->activate_installed = g_key_file_get_boolean(key_file, "system", "activate-installed", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->activate_installed = TRUE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "activate-installed", NULL);

	c->system_variant_type = R_CONFIG_SYS_VARIANT_NONE;

	/* parse 'variant-dtb' key */
	dtbvariant = g_key_file_get_boolean(key_file, "system", "variant-dtb", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		dtbvariant = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "variant-dtb", NULL);
	if (dtbvariant)
		c->system_variant_type = R_CONFIG_SYS_VARIANT_DTB;

	c->prevent_late_fallback = g_key_file_get_boolean(key_file, "system", "prevent-late-fallback", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->prevent_late_fallback = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "prevent-late-fallback", NULL);

	/* parse 'variant-file' key */
	variant_data = key_file_consume_string(key_file, "system", "variant-file", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_pointer(&variant_data, g_free);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (variant_data) {
		if (c->system_variant_type != R_CONFIG_SYS_VARIANT_NONE) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Only one of the keys 'variant-file', variant-dtb','variant-name' is allowed");
			return FALSE;
		}

		c->system_variant_type = R_CONFIG_SYS_VARIANT_FILE;
		c->system_variant = g_steal_pointer(&variant_data);
	}

	/* parse 'variant-name' key */
	variant_data = key_file_consume_string(key_file, "system", "variant-name", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_pointer(&variant_data, g_free);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (variant_data) {
		if (c->system_variant_type != R_CONFIG_SYS_VARIANT_NONE) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_INVALID_FORMAT,
					"Only one of the keys 'variant-file', variant-dtb','variant-name' is allowed");
			return FALSE;
		}

		c->system_variant_type = R_CONFIG_SYS_VARIANT_NAME;
		c->system_variant = g_steal_pointer(&variant_data);
	}

	/* parse data/status location
	 *
	 * We have multiple levels of backwards compatibility:
	 * - per-slot status and no shared data directory
	 *   (by default or explicitly with ``statusfile=per-slot``)
	 * - central status file and no shared data directory
	 *   (``statusfile=/data/central.raucs``)
	 * - central status file and shared data directory
	 *   (``statusfile=/data/central.raucs`` and ``data-directory=/data/rauc``)
	 * - central status file in shared data directory
	 *   (``data-directory=/data/rauc``, implies ``statusfile=/data/rauc/central.raucs``)
	 */
	c->data_directory = resolve_path_take(filename,
			key_file_consume_string(key_file, "system", "data-directory", &ierror));
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	c->statusfile_path = key_file_consume_string(key_file, "system", "statusfile", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_assert_null(c->statusfile_path);
		if (c->data_directory) {
			c->statusfile_path = g_build_filename(c->data_directory, "central.raucs", NULL);
		} else {
			if (filename)
				g_message("No data directory or status file set, falling back to per-slot status.\n"
						"Consider setting 'data-directory=<path>' or 'statusfile=<path>/per-slot' explicitly.");
			c->statusfile_path = g_strdup("per-slot");
		}
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (g_strcmp0(c->statusfile_path, "per-slot") == 0) {
		if (c->data_directory) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_DATA_DIRECTORY,
					"Using data-directory= with statusfile=per-slot is not supported.");
			return FALSE;
		}
		if (filename)
			g_message("Using per-slot statusfile. System status information not supported!");
	} else {
		gchar *resolved = resolve_path(filename, c->statusfile_path);
		g_free(c->statusfile_path);
		c->statusfile_path = resolved;
		g_message("Using central status file %s", c->statusfile_path);
	}

	/* parse bundle formats */
	c->bundle_formats_mask =
		1 << R_MANIFEST_FORMAT_PLAIN |
		        1 << R_MANIFEST_FORMAT_VERITY |
		        1 << R_MANIFEST_FORMAT_CRYPT;
	bundle_formats = key_file_consume_string(key_file, "system", "bundle-formats", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	} else {
		if (!parse_bundle_formats(&c->bundle_formats_mask, bundle_formats, &ierror)) {
			g_propagate_error(error, ierror);
			return FALSE;
		}
	}

	c->perform_pre_check = g_key_file_get_boolean(key_file, "system", "perform-pre-check", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
		c->perform_pre_check = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "system", "perform-pre-check", NULL);

	if (!check_remaining_keys(key_file, "system", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "system", NULL);

	return TRUE;
}

static gboolean parse_keyring_section(const gchar *filename, GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;
	gsize entries;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "keyring"))
		return TRUE;

	c->keyring_path = resolve_path_take(filename,
			key_file_consume_string(key_file, "keyring", "path", NULL));
	c->keyring_directory = resolve_path_take(filename,
			key_file_consume_string(key_file, "keyring", "directory", NULL));

	c->keyring_check_crl = g_key_file_get_boolean(key_file, "keyring", "check-crl", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		c->keyring_check_crl = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "keyring", "check-crl", NULL);

	c->keyring_allow_partial_chain = g_key_file_get_boolean(key_file, "keyring", "allow-partial-chain", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		c->keyring_allow_partial_chain = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "keyring", "allow-partial-chain", NULL);

	gboolean keyring_allow_single_signature = g_key_file_get_boolean(key_file, "keyring", "allow-single-signature", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		keyring_allow_single_signature = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "keyring", "allow-single-signature", NULL);
	if (!ENABLE_OPENSSL_VERIFY_PARTIAL && keyring_allow_single_signature) {
		g_set_error(
				error,
				G_KEY_FILE_ERROR,
				G_KEY_FILE_ERROR_INVALID_VALUE,
				"Keyring section option 'allow-single-signature' is not supported because OpenSSL does not define CMS_VERIFY_PARTIAL");
		return FALSE;
	}
	c->keyring_allow_single_signature = keyring_allow_single_signature;

	c->use_bundle_signing_time = g_key_file_get_boolean(key_file, "keyring", "use-bundle-signing-time", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		c->use_bundle_signing_time = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "keyring", "use-bundle-signing-time", NULL);

	c->keyring_check_purpose = key_file_consume_string(key_file, "keyring", "check-purpose", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		g_assert_null(c->keyring_check_purpose);
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	/* Rewrite 'codesign' check-purpose to RAUC's internal 'codesign-rauc' check-purpose
	 * to avoid conflicts with purpose definition from OpenSSL 3.2.0. */
	if (g_strcmp0(c->keyring_check_purpose, "codesign") == 0) {
		g_free(c->keyring_check_purpose);
		c->keyring_check_purpose = g_strdup("codesign-rauc");
	}

	c->keyring_allowed_signer_cns = g_key_file_get_string_list(key_file, "keyring", "allowed-signer-cns", &entries, &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "keyring", "allowed-signer-cns", NULL);

	if (!check_remaining_keys(key_file, "keyring", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "keyring", NULL);

	return TRUE;
}

static gboolean parse_casync_section(GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "casync"))
		return TRUE;

	c->store_path = key_file_consume_string(key_file, "casync", "storepath", NULL);
	c->tmp_path = key_file_consume_string(key_file, "casync", "tmppath", NULL);
	c->casync_install_args = key_file_consume_string(key_file, "casync", "install-args", NULL);
	c->use_desync = g_key_file_get_boolean(key_file, "casync", "use-desync", &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		c->use_desync = FALSE;
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_key(key_file, "casync", "use-desync", NULL);
	if (!check_remaining_keys(key_file, "casync", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "casync", NULL);

	return TRUE;
}

static gboolean parse_streaming_section(GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;
	gsize entries;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "streaming"))
		return TRUE;

	c->streaming_sandbox_user = key_file_consume_string(key_file, "streaming", "sandbox-user", NULL);
	c->streaming_tls_cert = key_file_consume_string(key_file, "streaming", "tls-cert", NULL);
	c->streaming_tls_key = key_file_consume_string(key_file, "streaming", "tls-key", NULL);
	c->streaming_tls_ca = key_file_consume_string(key_file, "streaming", "tls-ca", NULL);
	c->enabled_headers = g_key_file_get_string_list(key_file, "streaming", "send-headers", &entries, &ierror);
	if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND) ||
	    g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND)) {
		g_clear_error(&ierror);
	} else if (ierror) {
		g_propagate_error(error, ierror);
		return FALSE;
	} else {
		for (gsize j = 0; j < entries; j++) {
			if (!r_install_is_supported_http_header(c->enabled_headers[j])) {
				g_set_error(error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE,
						"Automatic HTTP header '%s' not supported", c->enabled_headers[j]);
				return FALSE;
			}
		}
	}
	g_key_file_remove_key(key_file, "streaming", "send-headers", NULL);
	if (!check_remaining_keys(key_file, "streaming", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "streaming", NULL);

	return TRUE;
}

static gboolean parse_encryption_section(const gchar *filename, GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "encryption"))
		return TRUE;

	c->encryption_key = resolve_path_take(filename,
			key_file_consume_string(key_file, "encryption", "key", NULL));
	c->encryption_cert = resolve_path_take(filename,
			key_file_consume_string(key_file, "encryption", "cert", NULL));
	if (!check_remaining_keys(key_file, "encryption", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "encryption", NULL);

	return TRUE;
}

static gboolean parse_autoinstall_section(const gchar *filename, GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "autoinstall"))
		return TRUE;

	c->autoinstall_path = resolve_path_take(filename,
			key_file_consume_string(key_file, "autoinstall", "path", NULL));
	if (!check_remaining_keys(key_file, "autoinstall", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "autoinstall", NULL);

	return TRUE;
}

static gboolean parse_handlers_section(const gchar *filename, GKeyFile *key_file, RaucConfig *c, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(key_file, FALSE);
	g_return_val_if_fail(c, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	if (!g_key_file_has_group(key_file, "handlers"))
		return TRUE;

	c->systeminfo_handler = resolve_path_take(filename,
			key_file_consume_string(key_file, "handlers", "system-info", NULL));

	c->preinstall_handler = resolve_path_take(filename,
			key_file_consume_string(key_file, "handlers", "pre-install", NULL));

	c->postinstall_handler = resolve_path_take(filename,
			key_file_consume_string(key_file, "handlers", "post-install", NULL));
	if (!check_remaining_keys(key_file, "handlers", &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	g_key_file_remove_group(key_file, "handlers", NULL);

	return TRUE;
}

static GHashTable *parse_slots(const char *filename, const char *data_directory, GKeyFile *key_file, GError **error)
{
	GError *ierror = NULL;
	g_auto(GStrv) groups = NULL;
	gsize group_count;
	g_autoptr(GHashTable) slots = NULL;
	g_autoptr(GList) slotlist = NULL;
	g_autoptr(GHashTable) bootnames = NULL;

	slots = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_slot_free);
	bootnames = g_hash_table_new(g_str_hash, g_str_equal);

	groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		g_auto(GStrv) groupsplit = g_strsplit(groups[i], ".", -1);

		/* We treat sections starting with "slot." as slots */
		if (g_str_equal(groupsplit[0], RAUC_SLOT_PREFIX)) {
			g_autoptr(RaucSlot) slot = g_new0(RaucSlot, 1);
			gchar* value;

			/* Assure slot strings consist of 3 parts, delimited by dots */
			if (g_strv_length(groupsplit) != 3) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_FORMAT,
						"Invalid slot name format: %s", groups[i]);
				return NULL;
			}

			value = g_strconcat(groupsplit[1], ".", groupsplit[2], NULL);
			slot->name = g_intern_string(value);
			g_free(value);

			/* If we have a data_directory, use a slot.<class>.<index>
			 * subdirectory for per-slot data. */
			if (data_directory)
				slot->data_directory = g_build_filename(data_directory, groups[i], NULL);

			slot->description = key_file_consume_string(key_file, groups[i], "description", NULL);

			slot->sclass = g_intern_string(groupsplit[1]);

			value = resolve_path_take(filename,
					key_file_consume_string(key_file, groups[i], "device", &ierror));
			if (!value) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			slot->device = value;

			value = key_file_consume_string(key_file, groups[i], "type", NULL);
			if (!value)
				value = g_strdup("raw");
			slot->type = value;

			if (!r_slot_is_valid_type(slot->type)) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_SLOT_TYPE,
						"Unsupported slot type '%s' for slot %s selected in system config", slot->type, slot->name);
				return NULL;
			}

			/* check if the device has an appropriate path */
			if (g_str_equal(slot->type, "jffs2") && !g_str_has_prefix(slot->device, "/dev/")) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_DEVICE,
						"%s: device must be located in /dev/ for jffs2", groups[i]);
				return NULL;
			}
			if (g_str_equal(slot->type, "boot-emmc") &&
			    (g_str_has_suffix(slot->device, "boot0") || g_str_has_suffix(slot->device, "boot1"))) {
				g_set_error(error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_DEVICE,
						"%s: 'device' must refer to the eMMC base device, not the boot partition", groups[i]);
				return NULL;
			}

			value = key_file_consume_string(key_file, groups[i], "extra-mkfs-opts", NULL);
			if (value != NULL) {
				if (!g_shell_parse_argv(value, NULL, &(slot->extra_mkfs_opts), &ierror)) {
					g_free(value);
					g_propagate_prefixed_error(error, ierror, "Failed to parse extra-mkfs-opts: ");
					return NULL;
				}
				g_free(value);
			}

			value = key_file_consume_string(key_file, groups[i], "bootname", NULL);

			slot->bootname = value;
			if (slot->bootname) {
				/* Ensure that the bootname does not contain whitespace or tab */
				if (!value_check_tab_whitespace(value, &ierror)) {
					g_propagate_prefixed_error(error, ierror,
							"Invalid bootname for slot %s: ", slot->name);
					return NULL;
				}

				/* check if we have seen this bootname on another slot */
				if (g_hash_table_contains(bootnames, slot->bootname)) {
					g_set_error(
							error,
							R_CONFIG_ERROR,
							R_CONFIG_ERROR_DUPLICATE_BOOTNAME,
							"Bootname '%s' is set on more than one slot",
							slot->bootname);
					return NULL;
				}
				g_hash_table_add(bootnames, slot->bootname);
			}

			/* Collect name of parent here for easing remaining key checking.
			 * Will be resolved to slot->parent pointer after config parsing loop. */
			slot->parent_name = key_file_consume_string(key_file, groups[i], "parent", NULL);

			slot->allow_mounted = g_key_file_get_boolean(key_file, groups[i], "allow-mounted", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->allow_mounted = FALSE;
				g_clear_error(&ierror);
			} else if (ierror) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			g_key_file_remove_key(key_file, groups[i], "allow-mounted", NULL);

			slot->readonly = g_key_file_get_boolean(key_file, groups[i], "readonly", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->readonly = FALSE;
				g_clear_error(&ierror);
			} else if (ierror) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			g_key_file_remove_key(key_file, groups[i], "readonly", NULL);

			slot->install_same = g_key_file_get_boolean(key_file, groups[i], "install-same", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				g_clear_error(&ierror);
				/* try also deprecated flag force-install-same */
				slot->install_same = g_key_file_get_boolean(key_file, groups[i], "force-install-same", &ierror);
				if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
					g_clear_error(&ierror);
					/* try also deprecated flag ignore-checksum */
					slot->install_same = g_key_file_get_boolean(key_file, groups[i], "ignore-checksum", &ierror);
					if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
						slot->install_same = TRUE;
						g_clear_error(&ierror);
					} else if (ierror) {
						g_propagate_error(error, ierror);
						return NULL;
					}
				} else if (ierror) {
					g_propagate_error(error, ierror);
					return NULL;
				}
			} else if (ierror) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			g_key_file_remove_key(key_file, groups[i], "install-same", NULL);
			g_key_file_remove_key(key_file, groups[i], "force-install-same", NULL);
			g_key_file_remove_key(key_file, groups[i], "ignore-checksum", NULL);

			slot->extra_mount_opts = key_file_consume_string(key_file, groups[i], "extra-mount-opts", NULL);

			slot->resize = g_key_file_get_boolean(key_file, groups[i], "resize", &ierror);
			if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
				slot->resize = FALSE;
				g_clear_error(&ierror);
			} else if (ierror) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			g_key_file_remove_key(key_file, groups[i], "resize", NULL);

			if (g_strcmp0(slot->type, "boot-mbr-switch") == 0 ||
			    g_strcmp0(slot->type, "boot-gpt-switch") == 0 ||
			    g_strcmp0(slot->type, "boot-raw-fallback") == 0) {
				slot->region_start = key_file_consume_binary_suffixed_string(key_file, groups[i],
						"region-start", &ierror);
				if (ierror) {
					g_propagate_prefixed_error(error, ierror, "mandatory for %s: ", slot->type);
					return NULL;
				}

				slot->region_size = key_file_consume_binary_suffixed_string(key_file, groups[i],
						"region-size", &ierror);
				if (ierror) {
					g_propagate_prefixed_error(error, ierror, "mandatory for %s: ", slot->type);
					return NULL;
				}
			}

			if (g_strcmp0(slot->type, "boot-emmc") == 0) {
				slot->size_limit = key_file_consume_binary_suffixed_string(key_file, groups[i],
						"size-limit", &ierror);
				if (g_error_matches(ierror, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)) {
					slot->size_limit = 0;
					g_clear_error(&ierror);
				} else if (ierror) {
					g_propagate_error(error, ierror);
					return NULL;
				}
			}

			if (!check_remaining_keys(key_file, groups[i], &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}

			g_key_file_remove_group(key_file, groups[i], NULL);

			g_hash_table_insert(slots, (gchar*)slot->name, slot);
			slot = NULL;
		}
	}

	/* Add parent pointers */
	slotlist = g_hash_table_get_keys(slots);
	for (GList *l = slotlist; l != NULL; l = l->next) {
		RaucSlot *slot;
		RaucSlot *parent;
		RaucSlot *child;

		slot = g_hash_table_lookup(slots, l->data);
		if (!slot->parent_name) {
			continue;
		}

		parent = g_hash_table_lookup(slots, slot->parent_name);
		if (!parent) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_PARENT,
					"Parent slot '%s' not found!", slot->parent_name);
			return NULL;
		}

		child = g_hash_table_lookup(slots, l->data);
		child->parent = parent;

		if (child->bootname) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_CHILD_HAS_BOOTNAME,
					"Child slot '%s' has bootname set",
					child->name);
			return NULL;
		}
	}

	if (!fix_grandparent_links(slots, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	return g_steal_pointer(&slots);
}

static GHashTable *parse_artifact_repos(const char *filename, const char *data_directory, GKeyFile *key_file, GError **error)
{
	GError *ierror = NULL;
	gsize group_count;

	g_autoptr(GHashTable) repos = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, r_artifact_repo_free);

	g_auto(GStrv) groups = g_key_file_get_groups(key_file, &group_count);
	for (gsize i = 0; i < group_count; i++) {
		g_auto(GStrv) groupsplit = g_strsplit(groups[i], ".", -1);

		/* We treat sections starting with "artifacts." as artifact repositories. */
		if (g_str_equal(groupsplit[0], "artifacts")) {
			g_autoptr(RArtifactRepo) repo = g_new0(RArtifactRepo, 1);

			/* Assure artifact repo strings consist of 2 parts, delimited by dots */
			if (g_strv_length(groupsplit) != 2) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_INVALID_FORMAT,
						"Invalid artifacts repo format: %s", groups[i]);
				return NULL;
			}
			repo->name = g_intern_string(groupsplit[1]);

			/* If we have a data_directory, use a artifacts.name subdirectory
			 * for per-repo data. */
			if (data_directory)
				repo->data_directory = g_build_filename(data_directory, groups[i], NULL);

			repo->description = key_file_consume_string(key_file, groups[i], "description", NULL);

			gchar* value = resolve_path_take(filename, key_file_consume_string(key_file, groups[i], "path", &ierror));
			if (!value) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			repo->path = value;

			value = key_file_consume_string(key_file, groups[i], "type", &ierror);
			if (!value) {
				g_propagate_error(error, ierror);
				return NULL;
			}
			repo->type = value;

			if (!r_artifact_repo_is_valid_type(repo->type)) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_ARTIFACT_REPO_TYPE,
						"Unsupported artifacts repo type '%s' for repo %s selected in system config", repo->type, repo->name);
				return NULL;
			}

			value = key_file_consume_string(key_file, groups[i], "parent-class", NULL);
			repo->parent_class = g_intern_string(value);
			g_free(value);
			if (repo->parent_class) {
				g_set_error(
						error,
						R_CONFIG_ERROR,
						R_CONFIG_ERROR_PARENT,
						"Parent slot classes are not yet supported for artifact repos");
				return NULL;
			}
			if (!check_remaining_keys(key_file, groups[i], &ierror)) {
				g_propagate_error(error, ierror);
				return NULL;
			}

			g_key_file_remove_group(key_file, groups[i], NULL);

			g_hash_table_insert(repos, (gchar*)repo->name, repo);
			repo = NULL;
		}
	}

	return g_steal_pointer(&repos);
}

static gboolean check_unique_slotclasses(RaucConfig *config, GError **error)
{
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, config->slots);
	gpointer value;
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		RaucSlot *slot = value;

		if (g_hash_table_contains(config->artifact_repos, slot->sclass)) {
			g_set_error(
					error,
					R_CONFIG_ERROR,
					R_CONFIG_ERROR_DUPLICATE_CLASS,
					"Existing slot class '%s' cannot be used as artifact repo name!", slot->sclass);
			return FALSE;
		}
	}
	return TRUE;
}

void r_config_file_modified_check(void)
{
	g_autoptr(GError) ierror = NULL;
	g_autofree gchar *data = NULL;
	gsize length;
	g_autofree gchar *new_checksum = NULL;

	if (!r_context()->config->file_checksum)
		return;

	if (!g_file_get_contents(r_context()->configpath, &data, &length, &ierror)) {
		g_warning("Failed to compare config: %s", ierror->message);
		return;
	}

	new_checksum = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar*) data, length);

	if (g_strcmp0(r_context()->config->file_checksum, new_checksum) != 0) {
		g_warning("System configuration file changed on disk! "
				"Still using old configuration! "
				"Please restart the rauc service.");
	}
}

/**
 * Parse a configuration, supplied as text in GKeyFile format.
 *
 * @param filename filename to resolve relative path names, or NULL
 * @param data the text to parse
 * @param length the length of data in bytes
 * @param error return location for a GError, or NULL
 *
 * @return a RaucConfig on success, NULL if there were errors
 */
static RaucConfig *parse_config(const gchar *filename, const gchar *data, gsize length, GError **error)
{
	GError *ierror = NULL;
	g_autoptr(RaucConfig) c = g_new0(RaucConfig, 1);
	g_autoptr(GKeyFile) key_file = NULL;

	g_return_val_if_fail(data, NULL);
	g_return_val_if_fail(error == NULL || *error == NULL, NULL);

	c->file_checksum = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar*) data, length);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_data(key_file, data, length, G_KEY_FILE_NONE, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* process overrides */
	for (GList *l = r_context_conf()->configoverride; l != NULL; l = l->next) {
		ConfigFileOverride *override = (ConfigFileOverride *)l->data;
		g_key_file_set_value(key_file, override->section, override->name, override->value);
	}

	/* parse [system] section */
	if (!parse_system_section(filename, key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [keyring] section */
	if (!parse_keyring_section(filename, key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [casync] section */
	if (!parse_casync_section(key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [streaming] section */
	if (!parse_streaming_section(key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [encryption] section */
	if (!parse_encryption_section(filename, key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [autoinstall] section */
	if (!parse_autoinstall_section(filename, key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [handlers] section */
	if (!parse_handlers_section(filename, key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	if (!r_event_log_parse_config_sections(key_file, c, &ierror)) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [slot.*.#] sections */
	c->slots = parse_slots(filename, c->data_directory, key_file, &ierror);
	if (!c->slots) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	/* parse [artifacts.*] sections */
	c->artifact_repos = parse_artifact_repos(filename, c->data_directory, key_file, &ierror);
	if (!c->artifact_repos) {
		g_propagate_error(error, ierror);
		return NULL;
	}

	if (!check_remaining_groups(key_file, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	return g_steal_pointer(&c);
}

gboolean default_config(RaucConfig **config, GError **error)
{
	GError *ierror = NULL;

	g_return_val_if_fail(config && *config == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* Use an empty system section to honor defaults from parse_system_section.
	 * After we have implemented explicit defaults there, we can use an empty
	 * string here. */
	const gchar *data = "[system]";
	RaucConfig *c = parse_config(NULL, data, strlen(data), &ierror);
	if (!c) {
		g_propagate_prefixed_error(error, ierror, "Failed to initialize default config: ");
		return FALSE;
	}

	*config = c;

	return TRUE;
}

gboolean load_config(const gchar *filename, RaucConfig **config, GError **error)
{
	GError *ierror = NULL;
	g_autofree gchar *data = NULL;
	gsize length;
	g_autoptr(RaucConfig) c = NULL;

	g_return_val_if_fail(filename, FALSE);
	g_return_val_if_fail(config && *config == NULL, FALSE);
	g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

	/* We store checksum for later comparison */
	if (!g_file_get_contents(filename, &data, &length, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}
	if (length == 0) {
		g_set_error(error, R_CONFIG_ERROR, R_CONFIG_ERROR_EMPTY_FILE,
				"Input file is empty");
		return FALSE;
	}

	c = parse_config(filename, data, length, &ierror);
	if (!c) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!check_unique_slotclasses(c, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	if (!check_config_target(c, &ierror)) {
		g_propagate_error(error, ierror);
		return FALSE;
	}

	/* on success, return config struct */
	*config = g_steal_pointer(&c);

	return TRUE;
}

gboolean check_config_target(const RaucConfig *config, GError **error)
{
	if (!config->system_compatible) {
		g_set_error_literal(error, R_CONFIG_ERROR, R_CONFIG_ERROR_MISSING_OPTION,
				"System compatible string is not set");
		return FALSE;
	}

	if (!config->system_bootloader) {
		g_set_error_literal(error, R_CONFIG_ERROR, R_CONFIG_ERROR_BOOTLOADER,
				"No bootloader selected in system config");
		return FALSE;
	}
	if (!r_boot_is_supported_bootloader(config->system_bootloader)) {
		g_set_error(error, R_CONFIG_ERROR, R_CONFIG_ERROR_BOOTLOADER,
				"Unsupported bootloader '%s' selected in system config",
				config->system_bootloader);
		return FALSE;
	}

	return TRUE;
}

RaucSlot *find_config_slot_by_device(RaucConfig *config, const gchar *device)
{
	g_return_val_if_fail(config, NULL);

	return r_slot_find_by_device(config->slots, device);
}

RaucSlot *find_config_slot_by_name(RaucConfig *config, const gchar *name)
{
	g_return_val_if_fail(config, NULL);
	g_return_val_if_fail(config->slots, NULL);
	g_return_val_if_fail(name, NULL);

	return g_hash_table_lookup(config->slots, name);
}

void free_config(RaucConfig *config)
{
	if (!config)
		return;

	g_free(config->system_compatible);
	g_free(config->system_min_bundle_version);
	g_free(config->system_variant);
	g_free(config->system_bootloader);
	g_free(config->system_bb_statename);
	g_free(config->system_bb_dtbpath);
	g_free(config->mount_prefix);
	g_free(config->store_path);
	g_free(config->tmp_path);
	g_free(config->casync_install_args);
	g_free(config->grubenv_path);
	g_free(config->data_directory);
	g_free(config->statusfile_path);
	g_free(config->keyring_path);
	g_free(config->keyring_directory);
	g_free(config->keyring_check_purpose);
	g_strfreev(config->keyring_allowed_signer_cns);
	g_free(config->autoinstall_path);
	g_free(config->systeminfo_handler);
	g_free(config->preinstall_handler);
	g_free(config->postinstall_handler);
	g_free(config->streaming_sandbox_user);
	g_free(config->streaming_tls_cert);
	g_free(config->streaming_tls_key);
	g_free(config->streaming_tls_ca);
	g_strfreev(config->enabled_headers);
	g_free(config->encryption_key);
	g_free(config->encryption_cert);
	g_list_free_full(config->loggers, (GDestroyNotify)r_event_log_free_logger);
	g_clear_pointer(&config->slots, g_hash_table_destroy);
	g_free(config->custom_bootloader_backend);
	g_free(config->file_checksum);
	g_clear_pointer(&config->artifact_repos, g_hash_table_destroy);
	g_free(config);
}
