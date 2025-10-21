/* Copyright r2ai - 2023-2025 - pancake */

#include "r2ai.h"

static void show_help() {
	printf ("Usage: r2ai [-vh] <prompt>\n"
	"  -v           Show version information\n"
	"  -h           Show this help message\n");
}

static void show_version() {
	printf ("r2ai " R2AI_VERSION "\n");
}

int main(int argc, const char **argv) {
	int c;

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "vh");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'v':
			show_version ();
			return 0;
		case 'h':
			show_help ();
			return 0;
		default:
			show_help ();
			return 1;
		}
	}

	if (opt.ind >= argc) {
		show_help ();
		return 1;
	}

	const char *prompt = argv[opt.ind];

	RCore *core = r_core_new ();
	char *err = NULL;

	R2AIArgs args = {
		.input = prompt,
		.error = &err,
		.dorag = false,
	};
	RCorePluginSession cps = {
		.core = core
	};
	r2ai_init (&cps);
	char *res = r2ai (&cps, args);
	if (res) {
		r_cons_println (core->cons, res);
		free (res);
	}
	free (err);
	r_cons_flush (core->cons);
	r2ai_fini (&cps);
	r_core_free (core);
	return 0;
}
