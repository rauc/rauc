#include "shell.h"

#include "utils.h"

void r_shell_from_manifest_meta(GPtrArray *shell_vars, const RaucManifest *manifest)
{
	g_return_if_fail(shell_vars);
	g_return_if_fail(manifest);

	if (!manifest->meta)
		return;

	GHashTableIter iter;
	g_hash_table_iter_init(&iter, manifest->meta);
	GHashTable *kvs;
	const gchar *group;
	while (g_hash_table_iter_next(&iter, (gpointer *)&group, (gpointer *)&kvs)) {
		g_autofree gchar *env_group = r_prepare_env_key(group, NULL);

		if (!env_group)
			continue;

		GHashTableIter kvs_iter;
		g_hash_table_iter_init(&kvs_iter, kvs);
		const gchar *key, *value;
		while (g_hash_table_iter_next(&kvs_iter, (gpointer *)&key, (gpointer *)&value)) {
			g_autofree gchar *env_key = r_prepare_env_key(key, NULL);

			if (!env_key)
				continue;

			r_ptr_array_add_printf(shell_vars, "RAUC_META_%s_%s=%s", env_group, env_key, value);
		}
	}
}
