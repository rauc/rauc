#pragma once

#include <glib.h>

typedef enum _RaucDMType {
	RAUC_DM_VERITY,
	RAUC_DM_CRYPT,
} RaucDMType;

typedef struct _RaucDM {
	RaucDMType type;

	/* common variables */
	gchar *uuid;
	gchar *lower_dev;
	gchar *upper_dev;
	guint64 data_size;

	/* dm-verity variables */
	gchar *root_digest;
	gchar *salt;

	/* dm-crypt variables */
	gchar *key;
} RaucDM;

/**
 * Allocates a new RaucDMVerity with uuid set.
 *
 * @return a pointer to the new RaucDMVerity
 */
RaucDM *r_dm_new_verity(void);

/**
 * Allocates a new RaucDMCrypt with uuid set.
 *
 * Free with r_dm_free_crypt.
 *
 * @return a pointer to the new RaucDMCrypt
 */
RaucDM *r_dm_new_crypt(void);

/**
 * Frees the memory allocated by a RaucDMVerity.
 *
 * @param dm_verity struct to free
 */
void r_dm_free(RaucDM *dm_verity);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(RaucDM, r_dm_free);

/**
 * Configure a dm-verity target in the kernel using the provided parameters and
 * return the resulting device name in the struct.
 *
 * @param dm_verity struct with configuration
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean r_dm_setup(RaucDM *dm_verity, GError **error);

/**
 * Remove a previously configured dm-verity target from the kernel.
 *
 * @param dm_verity struct with configuration
 * @param deferred TRUE if the kernel should remove the target when unused
 * @param error Return location for a GError
 *
 * @return TRUE on success, FALSE if an error occurred
 */
gboolean r_dm_remove(RaucDM *dm_verity, gboolean deferred, GError **error);
