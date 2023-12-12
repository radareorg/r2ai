
/* radare - Copyright 2023 pancake */

#define R_LOG_ORIGIN "r2ai"

#include <r_core.h>

static int r_cmd_r2ai_client(void *user, const char *input) {
	RCore *core = (RCore *) user;
	static RCoreHelpMessage help_msg_a2f = {
		"Usage:", "r2ai", "Use POST http://localhost:8000",
		"r2ai", " [arg]", "send a post request to talk to r2ai and print the output",
		NULL
	};
	if (r_str_startswith (input, "r2ai")) {
		const char *data = r_str_trim_head_ro (input + 4);
#if 0
		// XXX looks like there's a bug in RSocket.httpPost() that returns too early
		int code;
		char *res = r_socket_http_post ("http://localhost:8000", data, &code, NULL);
		if (code != 200) {
			R_LOG_ERROR ("Oops %d", code);
		}
#else
		char *res = r_sys_cmd_strf ("curl -d '%s' http://localhost:8000", data);
#endif
		r_cons_printf ("%s\n", res);
		free (res);
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_r2ai_client= {
	.meta = {
		.name = "r2ai-client",
		.desc = "remote r2ai client using http post",
		.author = "pancake",
		.license = "MIT",
	},
	.call = r_cmd_r2ai_client,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2ai_client,
	.version = R2_VERSION
};
#endif
