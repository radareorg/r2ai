#include <r_core.h>
#include "r2ai.h"

// TODO: not yet usable

int main(int argc, char **argv) {
	if (argc < 2) {
		eprintf ("Usage: r2ai <prompt>\n");
		return 1;
	}
	RCore *core = r_core_new ();
	char *err = NULL;
	R2AIArgs args = {
		.input = argv[1],
		.error = &err,
		.dorag = false
	};
	char *res = r2ai (core, args);
	R_LOG_INFO (res);
	free (res);
	r_core_free (core);
	return 0;
}
