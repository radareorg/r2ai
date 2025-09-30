/* Copyright r2ai - 2023-2025 - pancake */

#include <r_core.h>
#include "r2ai.h"

int main(int argc, char **argv) {
	if (argc < 2) {
		eprintf ("Usage: r2ai <prompt>\n");
		return 1;
	}

	const char *prompt = argv[1];

	RCore *core = r_core_new ();
	char *err = NULL;

	R2AIArgs args = {
		.input = prompt,
		.error = &err,
		.dorag = false,
	};

	char *res = r2ai (core, args);
	if (res) {
		R_LOG_INFO (res);
		free (res);
	}
	free (err);
	r_core_free (core);
	return 0;
}
