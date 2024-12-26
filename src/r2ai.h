#ifndef R2AI_H
#define R2AI_H

#include <r_core.h>
#include <r_util/r_json.h>

// anthropic
R_IPI char *r2ai_anthropic(const char *content, const char *model_name, char **error);
R_IPI char *r2ai_anthropic_stream(const char *content, const char *model_name, char **error);
// openai
R_IPI char *r2ai_openai(const char *content, const char *model, char **error);
R_IPI char *r2ai_openai_stream(const char *content, const char *model_name, char **error);
// openapi
R_IPI char *r2ai_openapi(const char *content, char **error);
R_IPI char *r2ai_ollama(const char *content, const char *model, char **error);
// gemini
R_IPI char *r2ai_gemini(const char *content, const char *model_name, char **error);
R_IPI char *r2ai_gemini_stream(const char *content, const char *model_name, char **error);

#endif
