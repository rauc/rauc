#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <context.h>
#include <signature.h>

#include "fuzz.h"

/* rauc itself limits signature/CMS sizes to 64 KiB by default */
#define FUZZ_MAX_SIG_SIZE (64*1024)

/*
 * Fuzzes the CMS signature handling in signature.c.
 *
 * The signature blob of a rauc bundle is fully attacker-controlled: it is
 * read from the bundle file and parsed as CMS/ASN.1 before any trust
 * decision. This harness drives the whole public signature surface over
 * one fuzzed CMS blob:
 *
 *   - pure parsers/dumpers: sigdata_to_string(), envelopeddata_to_string(),
 *     cms_is_detached(), cms_is_envelopeddata(),
 *     cms_get_unverified_manifest()
 *   - verification: cms_verify_sig() and cms_verify_bytes() against the
 *     in-repo developer keyring (including certificate chain extraction,
 *     pubkey hashing and chain formatting)
 *   - re-signing: cms_append_signature() with the in-repo developer key
 *
 * The keyring material is fixed trusted input (from the rauc repository);
 * only the CMS blob is fuzzed. This matches the threat model: an attacker
 * supplies the bundle, hence the signature, but not the verifier's CA.
 */

static gchar *fuzz_data_path(const gchar *relative)
{
	const gchar *out = g_getenv("OUT");

	if (out)
		return g_build_filename(out, relative, NULL);

	return g_strdup(relative);
}

/*
 * One-time context initialization.
 *
 * Points the context at the in-repo developer keyring and installs a
 * minimal system configuration enabling 'codesign-rauc' purpose checking,
 * so that the certificate purpose validation paths are exercised as well.
 * The context config file is fixed harness input, never fuzzed.
 *
 * This deliberately stays in R_CONTEXT_CONFIG_MODE_NONE (no target
 * setup): the target init path currently leaks the machine-id buffer on
 * systems with an empty /etc/machine-id (context.c get_machine_id(),
 * same pattern in get_boot_id()), which would abort every run in
 * leak detection. That defect is a real finding and is reported
 * upstream; the harness simply does not depend on the affected path.
 */
static void fuzz_init_context(void)
{
	static gboolean initialized = FALSE;
	g_autofree gchar *tmpdir = NULL;
	g_autofree gchar *confname = NULL;
	g_autofree gchar *keyringpath = NULL;
	g_autofree gchar *keyringdir = NULL;
	g_autofree gchar *content = NULL;
	g_autoptr(RaucConfig) config = NULL;
	g_autoptr(GError) error = NULL;

	if (initialized)
		return;

	fuzz_set_logging_func();

	if (!signature_init(&error)) {
		g_clear_error(&error);
		return;
	}

	keyringpath = fuzz_data_path("test/openssl-ca/dev-ca.pem");
	keyringdir = fuzz_data_path("test/openssl-ca/dir");

	tmpdir = g_dir_make_tmp("rauc-fuzz-XXXXXX", NULL);
	if (!tmpdir)
		return;

	confname = g_build_filename(tmpdir, "system.conf", NULL);
	if (!confname)
		goto out;

	content = g_strdup_printf(
			"[system]\n"
			"compatible=Fuzz Platform\n"
			"bootloader=uboot\n"
			"\n"
			"[keyring]\n"
			"path=%s\n"
			"directory=%s\n"
			"check-purpose=codesign-rauc\n",
			keyringpath,
			keyringdir);

	if (!g_file_set_contents(confname, content, -1, &error)) {
		g_clear_error(&error);
		goto out;
	}

	/* initialize the context like the bundle fuzzer does: NONE mode
	 * (no target setup, hence no machine-id handling) with the trusted
	 * developer keyring as override */
	r_context_conf()->keyringpath = g_steal_pointer(&keyringpath);
	r_context_conf()->keyringdirectory = g_steal_pointer(&keyringdir);

	(void)r_context();

	/* replace the default configuration with our parsed test config */
	if (load_config(confname, &config, &error)) {
		RaucConfig *defaultconf = r_context_conf()->config;

		r_context_conf()->config = g_steal_pointer(&config);

		free_config(defaultconf);
	} else {
		g_clear_error(&error);
	}

	initialized = TRUE;

out:
	if (confname)
		g_remove(confname);
	if (tmpdir)
		g_remove(tmpdir);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fuzz_init_context();

	if (size < 2 || size > FUZZ_MAX_SIG_SIZE)
		return 0;

	fuzz_set_logging_func();

	g_autoptr(GError) error = NULL;
	g_autoptr(GBytes) sig = g_bytes_new(data + 1, size - 1);

	switch (data[0] & 0x07) {
	case 0: {
		g_autofree gchar *text = sigdata_to_string(sig, &error);
		break;
	}
	case 1: {
		gboolean detached = FALSE;
		(void)cms_is_detached(sig, &detached, &error);
		break;
	}
	case 2:
		(void)cms_is_envelopeddata(sig);
		break;
	case 3: {
		g_autofree gchar *text = envelopeddata_to_string(sig, &error);
		break;
	}
	case 4: {
		g_autoptr(GBytes) manifest = NULL;
		(void)cms_get_unverified_manifest(sig, &manifest, &error);
		break;
	}
	case 5: {
		g_autoptr(X509_STORE) store = setup_x509_store(NULL, NULL, &error);
		g_autoptr(CMS_ContentInfo) cms = NULL;
		g_autoptr(GBytes) manifest = NULL;

		if (!store)
			break;

		(void)cms_verify_sig(sig, store, &cms, &manifest, &error);
		g_clear_error(&error);

		if (!cms)
			break;

		g_autoptr(R_X509_STACK) chain = NULL;
		if (!cms_get_cert_chain(cms, store, &chain, &error))
			break;

		g_auto(GStrv) hashes = get_pubkey_hashes(chain);
		g_autofree gchar *text = format_cert_chain(chain);
		break;
	}
	case 6: {
		static const gchar content_data[] = "rauc fuzz verification content";
		g_autoptr(GBytes) content = g_bytes_new_static(content_data, sizeof(content_data) - 1);
		g_autofree gchar *capath = fuzz_data_path("test/openssl-ca/dev-ca.pem");
		g_autoptr(X509_STORE) store = setup_x509_store(capath, NULL, &error);
		g_autoptr(CMS_ContentInfo) cms = NULL;
		g_autoptr(GBytes) manifest = NULL;

		if (!store)
			break;

		(void)cms_verify_bytes(content, sig, store, &cms, &manifest, &error);
		break;
	}
	case 7: {
		g_autofree gchar *certfile = fuzz_data_path("test/openssl-ca/dev/autobuilder-1.cert.pem");
		g_autofree gchar *keyfile = fuzz_data_path("test/openssl-ca/dev/private/autobuilder-1.pem");
		g_autoptr(GBytes) newsig = cms_append_signature(sig, certfile, keyfile, NULL, &error);
		break;
	}
	default:
		break;
	}

	return 0;
}
