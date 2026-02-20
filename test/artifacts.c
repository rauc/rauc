#include <stdio.h>
#include <locale.h>
#include <glib.h>

#include <artifacts.h>
#include <context.h>
#include <utils.h>

#include "common.h"

typedef struct {
	gchar *tmpdir;
	RArtifactRepo *repo;
} ArtifactsFixture;

static void show_tree(const gchar *path)
{
	g_autofree gchar *tree_cmd = g_strdup_printf("tree -a %s", path);

	system(tree_cmd);
}

static void artifacts_fixture_set_up(ArtifactsFixture *fixture, gconstpointer user_data)
{
	fixture->tmpdir = g_dir_make_tmp("rauc-artifacts-XXXXXX", NULL);
	g_assert_nonnull(fixture->tmpdir);

	g_assert(test_mkdir_relative(fixture->tmpdir, "repo", 0777) == 0);

	fixture->repo = g_new0(RArtifactRepo, 1);
	fixture->repo->name = g_intern_static_string("test-repo");
	fixture->repo->description = g_strdup("desc");
	fixture->repo->path = g_build_filename(fixture->tmpdir, "repo", NULL);
	fixture->repo->type = g_strdup("files");

	g_assert_true(r_artifact_repo_is_valid_type(fixture->repo->type));
}

static void artifacts_fixture_tear_down(ArtifactsFixture *fixture, gconstpointer user_data)
{
	show_tree(fixture->tmpdir);

	g_assert_true(rm_tree(fixture->tmpdir, NULL));
	g_free(fixture->tmpdir);
	g_clear_pointer(&fixture->repo, r_artifact_repo_free);
}

static RArtifact *create_random_artifact(const gchar *tmpdir, const gchar *name, gsize size, const guint32 seed)
{
	g_message("creating %s", name);

	g_autoptr(RArtifact) artifact = g_new0(RArtifact, 1);
	artifact->name = g_intern_string(name);
	g_autofree guint8 *content = random_bytes(size, seed);
	artifact->checksum.digest = g_compute_checksum_for_data(G_CHECKSUM_SHA256, content, size);
	artifact->checksum.size = size;
	artifact->checksum.type = G_CHECKSUM_SHA256;
	artifact->references = g_ptr_array_new();

	g_autofree gchar *pathname = g_strdup_printf("%s/.artifact-%s-%s", tmpdir, name, artifact->checksum.digest);

	if (!g_file_set_contents(pathname, (gchar *)content, size, NULL)) {
		return NULL;
	}

	return g_steal_pointer(&artifact);
}

static void test_repo_type(ArtifactsFixture *fixture, gconstpointer user_data)
{
	g_assert_true(r_artifact_repo_is_valid_type("files"));
	g_assert_true(r_artifact_repo_is_valid_type("trees"));
	g_assert_false(r_artifact_repo_is_valid_type("badtype"));
}

static void test_init(ArtifactsFixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	gboolean res = FALSE;

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_nonnull(fixture->repo->artifacts);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 0);

	res = r_artifact_repo_commit(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);
}

static void test_early_return(ArtifactsFixture *fixture, gconstpointer user_data)
{
	r_artifact_free(NULL);

	r_artifact_repo_free(NULL);
}

static void test_find(ArtifactsFixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	gboolean res = FALSE;

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	/* create artifact */
	RArtifact *artifact = create_random_artifact(fixture->repo->path, "a1", 64, 21799804);
	res = r_artifact_repo_insert(fixture->repo, artifact, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	g_assert_null(r_artifact_find(fixture->repo,
			g_intern_static_string("missing"),
			g_intern_static_string("foo")));

	g_assert_null(r_artifact_find(fixture->repo,
			g_intern_static_string("a1"),
			g_intern_static_string("foo")));

	g_assert_true(r_artifact_find(fixture->repo,
			g_intern_static_string("a1"),
			g_intern_static_string("6fb6a28f1b3d788150c8b02651575287ecb892312e4f077add0e84db55231d41")) == artifact);
}

static void test_create_load(ArtifactsFixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	gboolean res = FALSE;

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	/* create artifact */
	RArtifact *artifact = create_random_artifact(fixture->repo->path, "a1", 64, 21799804);
	res = r_artifact_repo_insert(fixture->repo, artifact, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	g_autofree gchar *a_filename = g_strdup_printf("%s/.artifact-a1-%s", fixture->repo->path, artifact->checksum.digest);
	g_autofree gchar *l_filename = g_strdup_printf("%s/a1", fixture->repo->path);

	g_assert_cmpstr(a_filename, ==, artifact->path);

	g_assert_false(g_file_test(a_filename, G_FILE_TEST_IS_SYMLINK));
	g_assert_true(g_file_test(a_filename, G_FILE_TEST_IS_REGULAR));
	g_assert_false(g_file_test(l_filename, G_FILE_TEST_EXISTS));

	/* add a link */
	r_artifact_activate(artifact, "");

	res = r_artifact_repo_commit(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	g_assert_true(g_file_test(l_filename, G_FILE_TEST_IS_SYMLINK));
	g_assert_true(g_file_test(l_filename, G_FILE_TEST_IS_REGULAR));

	/* check that duplicates are rejected */
	RArtifact *artifact_dup = create_random_artifact(fixture->repo->path, "a1", 64, 21799804);
	res = r_artifact_repo_insert(fixture->repo, artifact_dup, &error);
	g_assert_error(error, R_ARTIFACTS_ERROR, R_ARTIFACTS_ERROR_DUPLICATE);
	g_assert_false(res);
	g_clear_error(&error);
	g_clear_pointer(&artifact_dup, r_artifact_free);

	/* remove the link again */
	r_artifact_deactivate(artifact, "");

	res = r_artifact_repo_commit(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	show_tree(fixture->tmpdir);
	g_assert_false(g_file_test(l_filename, G_FILE_TEST_EXISTS));

	/* check that we still know about the deactivated artifact */
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	show_tree(fixture->tmpdir);

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 0);
}

static void test_create_load_parent(ArtifactsFixture *fixture, gconstpointer user_data)
{
	g_autoptr(GError) error = NULL;
	gboolean res = FALSE;

	fixture->repo->parent_class = g_intern_static_string("rootfs");

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	/* create artifact */
	RArtifact *artifact = create_random_artifact(fixture->repo->path, "a1", 64, 21799804);
	res = r_artifact_repo_insert(fixture->repo, artifact, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	g_autofree gchar *a_filename = g_strdup_printf("%s/.artifact-a1-%s", fixture->repo->path, artifact->checksum.digest);
	g_autofree gchar *l_filename = g_strdup_printf("%s/rootfs.0/a1", fixture->repo->path);

	g_assert_cmpstr(a_filename, ==, artifact->path);

	g_assert_false(g_file_test(a_filename, G_FILE_TEST_IS_SYMLINK));
	g_assert_true(g_file_test(a_filename, G_FILE_TEST_IS_REGULAR));
	g_assert_false(g_file_test(l_filename, G_FILE_TEST_EXISTS));

	/* add a link */
	r_artifact_activate(artifact, "rootfs.0");

	res = r_artifact_repo_commit(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_true(g_file_test(l_filename, G_FILE_TEST_IS_SYMLINK));
	g_assert_true(g_file_test(l_filename, G_FILE_TEST_IS_REGULAR));

	/* remove the link again */
	r_artifact_deactivate(artifact, "rootfs.0");

	show_tree(fixture->tmpdir);

	res = r_artifact_repo_commit(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	g_assert_false(g_file_test(l_filename, G_FILE_TEST_EXISTS));

	/* check that we still know about the deactivated artifact */
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 1);

	res = r_artifact_repo_prune(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);

	res = r_artifact_repo_prepare(fixture->repo, &error);
	g_assert_no_error(error);
	g_assert_true(res);
	g_assert_cmpuint(g_hash_table_size(fixture->repo->artifacts), ==, 0);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "C");

	r_context_conf()->configpath = g_strdup("test/test.conf");
	r_context();

	g_test_init(&argc, &argv, NULL);

	g_test_add("/artifacts/repo_type", ArtifactsFixture, NULL,
			NULL, test_repo_type,
			NULL);

	g_test_add("/artifacts/init", ArtifactsFixture, NULL,
			artifacts_fixture_set_up, test_init,
			artifacts_fixture_tear_down);

	g_test_add("/artifacts/early_return", ArtifactsFixture, NULL,
			artifacts_fixture_set_up, test_early_return,
			artifacts_fixture_tear_down);

	g_test_add("/artifacts/find", ArtifactsFixture, NULL,
			artifacts_fixture_set_up, test_find,
			artifacts_fixture_tear_down);

	g_test_add("/artifacts/create_load", ArtifactsFixture, NULL,
			artifacts_fixture_set_up, test_create_load,
			artifacts_fixture_tear_down);

	g_test_add("/artifacts/create_load_parent", ArtifactsFixture, NULL,
			artifacts_fixture_set_up, test_create_load_parent,
			artifacts_fixture_tear_down);

	return g_test_run();
}
