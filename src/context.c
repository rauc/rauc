#include <config_file.h>
#include <signature.h>

#include "context.h"

RaucContext *context = NULL;
gboolean context_ready = FALSE;

void r_context_alloc(void) {
	g_assert_null(context);

	context = g_new0(RaucContext, 1);
}

void r_context_init(void) {
	gboolean res = TRUE;

	g_assert_false(context_ready);
	g_assert_nonnull(context);

	if (context->configpath == NULL)
		context->configpath = g_strdup("/etc/rauc/system.conf");
	if (context->config == NULL)
		res = load_config(context->configpath, &context->config);

	if (!res)
		g_error("failed to initialize context");

	signature_init();

	context_ready = TRUE;
}

RaucContext *r_context(void) {
	if (context != NULL)
		return context;

	r_context_alloc();
	r_context_init();

	return context;
}
