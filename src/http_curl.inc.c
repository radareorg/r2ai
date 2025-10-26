#include "r2ai.h"
#include <signal.h>
#include <time.h>

// System curl implementations

HttpResponse *system_curl_post_file(const HTTPRequest *request) {
	int timeout = request->config.timeout;
	if (!request->url || !request->headers || !request->data) {
		return NULL;
	}

	// Create a temporary file for the data
	char *temp_file = r_file_temp ("r2ai_data");
	if (!temp_file) {
		R_LOG_ERROR ("Failed to create temporary file for curl data");
		return NULL;
	}

	// Write data to the temporary file
	if (!r_file_dump (temp_file, (const ut8 *)request->data, strlen (request->data), 0)) {
		R_LOG_ERROR ("Failed to write data to temporary file");
		free (temp_file);
		return NULL;
	}

	HttpResponse *result = NULL;

#ifdef _WIN32
	// On Windows, use PowerShell for HTTP requests
	// Read file content
	char *data_to_send = r_file_slurp (temp_file, NULL);
	if (!data_to_send) {
		r_file_rm (temp_file);
		free (temp_file);
		return NULL;
	}

	HttpResponse *result = windows_http_post (request->url, request->headers, data_to_send, timeout);

	free (data_to_send);
	r_file_rm (temp_file);
	free (temp_file);
#else
	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	for (int i = 0; request->headers[i] != NULL; i++) {
		r_strbuf_appendf (cmd, " -H \"%s\"", request->headers[i]);
	}

	// Add data file with @ prefix for curl
	r_strbuf_appendf (cmd, " -X POST -d @%s \"%s\"", temp_file, request->url);

	// Execute the curl command
	char *cmd_str = r_strbuf_drain (cmd);
	r_sys_setenv ("R2_CURL", "1"); // Ensure R2 uses system curl

	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

	free (cmd_str);
	r_file_rm (temp_file);
	free (temp_file);

	// We can't easily get the HTTP status code using this method
	// Let's assume 200 if we got a response, and 0 otherwise
	if (response) {
		result = R_NEW0 (HttpResponse);
		if (result) {
			result->body = response;
			result->code = 200;
			result->length = strlen (response);
		}
	} else {
		result = NULL;
	}
#endif
	return result;
}

HttpResponse *system_curl_get(const HTTPRequest *request) {
	int timeout = request->config.timeout;
	if (!request->url) {
		return NULL;
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local (&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	HttpResponse *result = NULL;

#ifdef _WIN32
	HttpResponse *result = windows_http_get (request->url, request->headers, timeout);
#else
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

	// Set an alarm to limit the request time
#if R2__UNIX__
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (timeout); // Use configured timeout
#endif

	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

	// Clear the alarm
#if R2__UNIX__
	alarm (0);
#endif

	free (cmd_str);

	// Check if we were interrupted
	if (r2ai_http_interrupted) {
		R_LOG_DEBUG ("HTTP request was interrupted by user");
		free (response);
		restore_sigint_handler_local (r2ai_old_sig, r2ai_old_is_sigaction);
		return NULL;
	}

	// We can't easily get the HTTP status code using this method
	// Let's assume 200 if we got a response, and 0 otherwise
	if (response) {
		result = R_NEW0 (HttpResponse);
		if (result) {
			result->body = response;
			result->code = 200;
			result->length = strlen (response);
		}
	} else {
		result = NULL;
	}
#endif

	// Restore the original signal handler
	restore_sigint_handler_local (r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}