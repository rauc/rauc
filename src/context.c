#include <config_file.h>
#include <network.h>
#include <signature.h>

#include "context.h"

RaucContext *context = NULL;

static void r_context_configure(void) {
	gboolean res = TRUE;

	g_assert_nonnull(context);
	g_assert_false(context->busy);

	g_clear_pointer(&context->config, free_config);
	res = load_config(context->configpath, &context->config, NULL);

	if (context->mountprefix) {
		g_free(context->config->mount_prefix);
		context->config->mount_prefix = g_strdup(context->mountprefix);
	}

	if (!res)
		g_error("failed to initialize context");

	context->pending = FALSE;
}

gboolean r_context_get_busy(void) {
	if (context == NULL) {
		return FALSE;
	}

	return context->busy;
}

void r_context_set_busy(gboolean busy) {
	g_assert_nonnull(context);
	g_assert(context->busy != busy);

	if (!context->busy && context->pending)
		r_context_configure();

	context->busy = busy;
}

RaucContext *r_context_conf(void) {
	if (context == NULL) {
		network_init();
		signature_init();

		context = g_new0(RaucContext, 1);
		context->configpath = g_strdup("/etc/rauc/system.conf");
	}

	g_assert_false(context->busy);

	context->pending = TRUE;

	return context;
}

const RaucContext *r_context(void) {
	g_assert_nonnull(context);

	if (context->pending)
		r_context_configure();

	return context;
}
