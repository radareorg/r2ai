#ifndef R2AI_H
#define R2AI_H

#include <r_core.h>
#include <r_util/r_json.h>
#include "r_vdb.h"

// anthropic
R_IPI char *r2ai_anthropic(const char *content, const char *model_name, char **error);
R_IPI char *r2ai_anthropic_stream(const char *content, const char *model_name, char **error);
// openai
R_IPI char *r2ai_openai(RCore *core, const char *content, const char *model, char **error);
R_IPI char *r2ai_openai_stream(RCore *core, const char *content, const char *model_name, char **error);
// xai
R_IPI char *r2ai_xai(RCore *core, const char *content, char **error);
R_IPI char *r2ai_xai_stream(RCore *core, const char *content, char **error);
// openapi
R_IPI char *r2ai_openapi(const char *content, char **error);
R_IPI char *r2ai_ollama(RCore *core, const char *content, const char *model, char **error);
// gemini
R_IPI char *r2ai_gemini(const char *content, const char *model_name, char **error);
R_IPI char *r2ai_gemini_stream(const char *content, const char *model_name, char **error);

// auto mode
R_IPI void cmd_r2ai_a(RCore *core, const char *e);
R_IPI char *r2ai(RCore *core, const char *input, char **error);

#endif
