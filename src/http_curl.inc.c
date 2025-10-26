#include "r2ai.h"
#include <signal.h>
#include <time.h>

// System curl implementations

char *system_curl_post_file(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	R2AI_HttpConfig config = get_http_config (core);
	int timeout = config.timeout;
	bool use_files = core ? r_config_get_b (core->config, "r2ai.http.use_files") : false;
	if (!url || !headers || !data || !code) {
		return NULL;
	}

	// Create a temporary file for the data
	char *temp_file = r_file_temp ("r2ai_data");
	if (!temp_file) {
		R_LOG_ERROR ("Failed to create temporary file for curl data");
		return NULL;
	}

	if (use_files) {
		// Write data to the temporary file
		if (!r_file_dump (temp_file, (const ut8 *)data, strlen (data), 0)) {
			R_LOG_ERROR ("Failed to write data to temporary file");
			free (temp_file);
			return NULL;
		}
	}

	char *result = NULL;

#ifdef _WIN32
	// On Windows, use PowerShell for HTTP requests
	char *data_to_send = NULL;
	if (use_files) {
		// Read file content
		data_to_send = r_file_slurp (temp_file, NULL);
		if (!data_to_send) {
			r_file_rm (temp_file);
			free (temp_file);
			return NULL;
		}
	} else {
		data_to_send = (char *)data;
	}

	result = windows_http_post (url, headers, data_to_send, code, rlen, timeout);

	if (use_files) {
		free (data_to_send);
	}
	r_file_rm (temp_file);
	free (temp_file);
#else
	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	for (int i = 0; headers[i] != NULL; i++) {
		r_strbuf_appendf (cmd, " -H \"%s\"", headers[i]);
	}

	if (use_files) {
		// Add data file with @ prefix for curl
		r_strbuf_appendf (cmd, " -X POST -d @%s \"%s\"", temp_file, url);
	} else {
		char *s = strdup (data);
		s = r_str_replace_all (s, "\\", "\\\\");
		// s = r_str_replace_all (s, "'", "\\'");
		s = r_str_replace_all (s, "'", "'\\''");
		r_strbuf_appendf (cmd, " -X POST -d '%s' \"%s\"", s, url);
		free (s);
	}

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
		*code = 200;
		if (rlen) {
			*rlen = strlen (response);
		}
		result = response;
	} else {
		*code = 0;
	}
#endif
	return result;
}

char *system_curl_get(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	R2AI_HttpConfig config = get_http_config (core);
	int timeout = config.timeout;
	if (!url || !code) {
		return NULL;
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local (&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	char *result = NULL;

#ifdef _WIN32
	result = windows_http_get (url, headers, code, rlen, timeout);
#else
	// Compose curl command
	RStrBuf *cmd = r_strbuf_new ("curl -s");

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	if (headers) {
		for (int i = 0; headers[i] != NULL; i++) {
			r_strbuf_appendf (cmd, " -H \"%s\"", headers[i]);
		}
	}

	// Add URL
	r_strbuf_appendf (cmd, " \"%s\"", url);

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
		*code = 200;
		if (rlen) {
			*rlen = strlen (response);
		}
		result = response;
	} else {
		*code = 0;
	}
#endif

	// Restore the original signal handler
	restore_sigint_handler_local (r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}