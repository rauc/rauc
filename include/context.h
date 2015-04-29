#pragma once

#include <glib.h>

#include "config_file.h"

typedef struct {
	/* system configuration data */
	gchar *configpath;
	RaucConfig *config;

	/* signing data */
	gchar *certpath;
	gchar *keypath;
} RaucContext;

void r_context_alloc(void);
void r_context_init(void);

RaucContext *r_context(void);
