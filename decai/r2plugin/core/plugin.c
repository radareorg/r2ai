/* decai - LGPL - Copyright 2026 - pancake */

#include <r_core.h>

// generated from ../decai.r2.js, see ../deps.mk
extern const unsigned char decai_qjs[];
extern const unsigned int decai_qjs_len;

static bool decai_init(RCorePluginSession *cps) {
	r_core_script_embed (cps->core, "decai", "qjs", (const char *)decai_qjs, (int)decai_qjs_len);
	return true;
}

static bool decai_call(RCorePluginSession *cps, const char *input) {
	return false;
}

RCorePlugin r_core_plugin_decai = {
	.meta = {
		.name = "decai",
		.desc = "AI decompiler (embedded decai.r2.js)",
		.author = "pancake",
		.license = "MIT",
	},
	.init = decai_init,
	.call = decai_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_decai,
	.version = R2_VERSION,
};
#endif
