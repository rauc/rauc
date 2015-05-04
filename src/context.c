#include <config_file.h>
#include <signature.h>

#include "context.h"

RaucContext *context = NULL;

static void r_context_configure(void) {
	gboolean res = TRUE;

	g_assert_nonnull(context);
	g_assert_false(context->busy);

	g_clear_pointer(&context->config, free_config);
	res = load_config(context->configpath, &context->config);

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

	context->busy = busy;
}

RaucContext *r_context_conf(void) {
	if (context == NULL) {
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
