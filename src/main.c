/* Copyright r2ai - 2023-2025 - pancake */

#include "r2ai_priv.h"

static void show_help() {
	printf ("Usage: r2ai [-vhp:m:q:] <prompt>\n"
	"  -v           Show version information\n"
	"  -h           Show this help message\n"
	"  -p <provider> Select LLM provider\n"
	"  -m <model>   Select LLM model\n"
	"  -q <query>   Execute predefined prompt query (can be used multiple times)\n");
}

static void show_version() {
	printf ("r2ai " R2AI_VERSION "\n");
}

int main(int argc, const char **argv) {
	int c;
	const char *provider = NULL;
	const char *model = NULL;
	RList *queries = r_list_newf (free);

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "vhp:m:q:");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'v':
			show_version ();
			r_list_free (queries);
			return 0;
		case 'h':
			show_help ();
			r_list_free (queries);
			return 0;
		case 'p':
			provider = opt.arg;
			break;
		case 'm':
			model = opt.arg;
			break;
		case 'q':
			r_list_append (queries, strdup (opt.arg));
			break;
		default:
			show_help ();
			r_list_free (queries);
			return 1;
		}
	}

	RCore *core = r_core_new ();
	RCorePluginSession cps = {
		.core = core
	};
	r2ai_init (&cps);

	// Process queries if any
	if (!r_list_empty (queries)) {
		RListIter *iter;
		char *query;
		r_list_foreach (queries, iter, query) {
			r2ai_cmd_q (&cps, query);
		}
	} else {
		if (opt.ind >= argc) {
			show_help ();
			r_list_free (queries);
			r2ai_fini (&cps);
			r_core_free (core);
			return 1;
		}

		const char *prompt = argv[opt.ind];

		char *err = NULL;
		R2AIArgs args = {
			.input = prompt,
			.provider = provider,
			.model = model,
			.error = &err,
			.dorag = false,
		};
		char *res = r2ai (&cps, args);
		if (res) {
			r_cons_println (core->cons, res);
			free (res);
		}
		free (err);
		r_cons_flush (core->cons);
	}

	r_list_free (queries);
	r2ai_fini (&cps);
	r_core_free (core);
	return 0;
}
