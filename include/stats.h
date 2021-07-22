#pragma once

#include <glib.h>

struct RaucStats {
	gdouble values[64];
	guint64 count, next;
	gdouble sum;
	gdouble min, max;
};

void r_stats_init(struct RaucStats *stats);

void r_stats_add(struct RaucStats *stats, gdouble value);

gdouble r_stats_get_avg(const struct RaucStats *stats);

gdouble r_stats_get_recent_avg(const struct RaucStats *stats);

void r_stats_show(const struct RaucStats *stats, const gchar *prefix);
