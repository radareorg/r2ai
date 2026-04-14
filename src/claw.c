/* r2ai - Copyright 2026 pancake */

#define R_LOG_ORIGIN "r2ai.claw"

#include "r2ai.h"
#include "r2ai_priv.h"

#define CLAW_DEFAULT_IDENTITY \
	"- Name: r2clippy\n" \
	"- A fun, useful reverse engineering sidekick living inside radare2\n" \
	"- Speaks short, make jokes, but always goes to the point\n" \
	"- Loves assembly, expert cracker, eats hex dumps for breakfast and it's smart building clever unix one-liners"

#define CLAW_DEFAULT_SOUL \
	"- Useful first, fun second\n" \
	"- Show, don't preach: prefer concrete r2 commands and runnable examples\n" \
	"- Curious about every binary, never bored\n" \
	"- Admit when something is unclear instead of guessing"

#define CLAW_PROMPT_RULES \
	"Output between 2 and 5 short markdown bullet points - be flexible, do not pad. " \
	"Output ONLY the bullets, no preface, no explanation, no code fences."

typedef struct {
	const char *rel;
	const char *tag;
	const char *def;
	const char *prompt;
} ClawFile;

static const ClawFile CLAW_FILES[] = {
	{ ".config/r2ai/IDENTITY.md", "identity", CLAW_DEFAULT_IDENTITY,
		"Generate an IDENTITY for a fun and useful reverse engineering assistant living in radare2. "
		"IDENTITY defines WHO the assistant is: name, vibe, voice, style. "
		"Be invented, surprising and unique each time. " CLAW_PROMPT_RULES },
	{ ".config/r2ai/SOUL.md", "soul", CLAW_DEFAULT_SOUL,
		"Generate a SOUL for a fun and useful reverse engineering assistant living in radare2. "
		"SOUL defines HOW the assistant behaves: values, opinions, rules, character. "
		"Useful first, fun second; have a clear personal voice. " CLAW_PROMPT_RULES },
};
#define CLAW_NFILES ((int)(sizeof (CLAW_FILES) / sizeof (CLAW_FILES[0])))

R_API bool r2ai_claw_exists(void) {
	int i;
	for (i = 0; i < CLAW_NFILES; i++) {
		char *path = r_file_home (CLAW_FILES[i].rel);
		bool e = path && r_file_exists (path);
		free (path);
		if (e) {
			return true;
		}
	}
	return false;
}

static char *claw_personality(void) {
	RStrBuf *sb = r_strbuf_new ("");
	int i;
	for (i = 0; i < CLAW_NFILES; i++) {
		char *path = r_file_home (CLAW_FILES[i].rel);
		char *content = path? r_file_slurp (path, NULL): NULL;
		free (path);
		r_strbuf_appendf (sb, "\n<%s>\n%s\n</%s>\n",
			CLAW_FILES[i].tag,
			content? content: CLAW_FILES[i].def,
			CLAW_FILES[i].tag);
		free (content);
	}
	return r_strbuf_drain (sb);
}

R_API char *r2ai_claw_system_prompt(const char *base) {
	if (!r2ai_claw_exists ()) {
		return strdup (base? base: "");
	}
	char *personality = claw_personality ();
	char *result = r_str_newf ("%s%s", base? base: "", personality);
	free (personality);
	return result;
}

static char *claw_generate(RCorePluginSession *cps, const char *prompt, const char *extra) {
	char *full = R_STR_ISNOTEMPTY (extra)
		? r_str_newf ("%s\n\nAdditional hints from the user: %s", prompt, extra)
		: strdup (prompt);
	char *err = NULL;
	R2AIArgs args = {
		.input = full,
		.system_prompt = "You are a creative writer crafting concise personality files.",
		.error = &err,
		.dorag = false
	};
	char *res = r2ai (cps, args);
	free (full);
	if (err) {
		R_LOG_ERROR ("%s", err);
		free (err);
	}
	return res;
}

R_API void r2ai_claw_show(RCorePluginSession *cps) {
	RCore *core = cps->core;
	int i;
	for (i = 0; i < CLAW_NFILES; i++) {
		char *path = r_file_home (CLAW_FILES[i].rel);
		char *content = path? r_file_slurp (path, NULL): NULL;
		if (content) {
			r_cons_printf (core->cons, "\n=== %s ===\n%s\n", path, content);
		}
		free (content);
		free (path);
	}
}

R_API void r2ai_claw_create(RCorePluginSession *cps, const char *user_extra) {
	if (!r2ai_claw_exists ()) {
		char *cfg = r_file_home (".config/r2ai");
		r_sys_mkdirp (cfg);
		free (cfg);
		int i;
		for (i = 0; i < CLAW_NFILES; i++) {
			const ClawFile *f = &CLAW_FILES[i];
			R_LOG_INFO ("Generating %s", f->tag);
			char *text = claw_generate (cps, f->prompt, user_extra);
			if (R_STR_ISEMPTY (text)) {
				R_LOG_ERROR ("Failed to generate %s", f->tag);
				free (text);
				continue;
			}
			char *path = r_file_home (f->rel);
			if (!path || !r_file_dump (path, (const ut8 *)text, strlen (text), false)) {
				R_LOG_ERROR ("Cannot write %s", path? path: f->rel);
			}
			free (path);
			free (text);
		}
	}
	r2ai_claw_show (cps);
	r_cons_printf (cps->core->cons, "\n%s.\n", R2AI_CLAW_HINT);
}

R_API void r2ai_claw_edit(RCorePluginSession *cps) {
	if (!r2ai_claw_exists ()) {
		R_LOG_ERROR ("No personality files, run 'r2ai -id' to generate them first");
		return;
	}
	int i;
	for (i = 0; i < CLAW_NFILES; i++) {
		char *path = r_file_home (CLAW_FILES[i].rel);
		if (path && r_file_exists (path)) {
			r_cons_editor (cps->core->cons, path, NULL);
		}
		free (path);
	}
}

R_API void r2ai_claw_delete(RCorePluginSession *cps) {
	RCore *core = cps->core;
	if (!r2ai_claw_exists ()) {
		r_cons_printf (core->cons, "No personality files to delete.\n");
		return;
	}
	int i;
	for (i = 0; i < CLAW_NFILES; i++) {
		char *path = r_file_home (CLAW_FILES[i].rel);
		if (path && r_file_exists (path) && r_file_rm (path)) {
			r_cons_printf (core->cons, "Deleted %s\n", path);
		}
		free (path);
	}
}
