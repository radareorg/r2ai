#include "r2ai.h"
#include <signal.h>
#include <time.h>

// System curl implementations

HttpResponse system_curl_post_file(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	int timeout = request->config.timeout;
	if (!request->url || !request->headers || !request->data) {
		return error;
	}

	// Create a temporary file for the data
	char *temp_file = r_file_temp ("r2ai_data");
	if (!temp_file) {
		R_LOG_ERROR ("Failed to create temporary file for curl data");
		return error;
	}

	// Write data to the temporary file
	if (!r_file_dump (temp_file, (const ut8 *)request->data, strlen (request->data), 0)) {
		R_LOG_ERROR ("Failed to write data to temporary file");
		free (temp_file);
		return error;
	}

	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			r_strbuf_appendf (cmd, " -H \"%s\"", request->headers[i]);
		}
	}

	// Add URL
	r_strbuf_appendf (cmd, " \"%s\"", request->url);

	// Execute the curl command
	char *cmd_str = r_strbuf_drain (cmd);
	r_sys_setenv ("R2_CURL", "1"); // Ensure R2 uses system curl

	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

	free (cmd_str);

	// We can't easily get the HTTP status code using this method
	// Let's assume 200 if we got a response, and 0 otherwise
	if (response) {
		return (HttpResponse){ .body = response, .code = 200, .length = strlen (response) };
	} else {
		return (HttpResponse){ .body = NULL, .code = -1, .length = 0 };
	}
}

HttpResponse system_curl_get(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	int timeout = request->config.timeout;
	if (!request->url) {
		return error;
	}

	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			r_strbuf_appendf (cmd, " -H \"%s\"", request->headers[i]);
		}
	}

	// Add URL
	r_strbuf_appendf (cmd, " \"%s\"", request->url);

	// Execute the curl command
	char *cmd_str = r_strbuf_drain (cmd);
	r_sys_setenv ("R2_CURL", "1"); // Ensure R2 uses system curl

	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

	free (cmd_str);

	// We can't easily get the HTTP status code using this method
	// Let's assume 200 if we got a response, and 0 otherwise
	if (response) {
		return (HttpResponse){ .body = response, .code = 200, .length = strlen (response) };
	}
	return error;
}

HttpResponse system_curl_post(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	int timeout = request->config.timeout;
	if (!request->url || !request->data) {
		return error;
	}

	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s -X POST");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			r_strbuf_appendf (cmd, " -H \"%s\"", request->headers[i]);
		}
	}

	// Add data
	r_strbuf_appendf (cmd, " -d \"%s\"", request->data);

	// Add URL
	r_strbuf_appendf (cmd, " \"%s\"", request->url);

	// Execute the curl command
	char *cmd_str = r_strbuf_drain (cmd);
	r_sys_setenv ("R2_CURL", "1"); // Ensure R2 uses system curl

	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

	free (cmd_str);

	// We can't easily get the HTTP status code using this method
	// Let's assume 200 if we got a response, and 0 otherwise
	if (response) {
		return (HttpResponse){ .body = response, .code = 200, .length = strlen (response) };
	} else {
		return (HttpResponse){ .body = NULL, .code = -1, .length = 0 };
	}
}
