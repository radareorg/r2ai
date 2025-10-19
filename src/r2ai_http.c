#include "r2ai.h"
#include <signal.h>
#include <time.h>

/**
 * r2ai HTTP implementation with:
 * - Interrupt handling (SIGINT)
 * - Timeout handling
 * - Rate limiting with exponential backoff
 * - Retrying on errors (429, 5xx)
 *
 * Configuration variables:
 * - r2ai.http.timeout: Request timeout in seconds (default: 120)
 * - r2ai.http.max_retries: Maximum number of retry attempts (default: 3)
 * - r2ai.http.max_backoff: Maximum backoff time in seconds (default: 30)
 */

// Global flag for tracking interrupt status
static volatile sig_atomic_t r2ai_http_interrupted = 0;

// Signal handler for SIGINT
static void r2ai_http_sigint_handler(int sig) {
    (void)sig;
    r2ai_http_interrupted = 1;
}

/*
 * Portable install/restore helpers for SIGINT handler.
 * Some platforms may not have struct sigaction available; use signal()
 * as a fallback. We allocate storage for the old handler when
 * sigaction is available so the restore function can restore it later.
 */
static void install_sigint_handler_local(void **out_old, int *out_old_is_sigaction) {
    void (*old)(int) = signal (SIGINT, r2ai_http_sigint_handler);
    *out_old = (void *)old;
    *out_old_is_sigaction = 0;
}

static void restore_sigint_handler_local(void *old, int old_is_sigaction) {
    (void)old_is_sigaction;
    signal (SIGINT, (void (*)(int))old);
}

// Helper function to implement exponential backoff sleep
static void r2ai_sleep_with_backoff(int retry_count, int max_sleep_seconds) {
	// Calculate sleep time with exponential backoff: 2^retry * base_time with jitter
	int base_time_ms = 1000; // 500ms base time
	int max_sleep_ms = max_sleep_seconds * 1000;

	// Calculate exponential delay time with upper bound
	int delay_ms = (1 << retry_count) * base_time_ms;
	if (delay_ms > max_sleep_ms) {
		delay_ms = max_sleep_ms;
	}

	// Add jitter (±20%)
	int jitter = delay_ms / 5;
	if (jitter > 0) {
		srand (time (NULL) + retry_count);
		delay_ms += (rand () % (jitter * 2)) - jitter;
	}

	// Ensure delay stays positive and within max limits
	if (delay_ms <= 0) {
		delay_ms = base_time_ms;
	} else if (delay_ms > max_sleep_ms) {
		delay_ms = max_sleep_ms;
	}

	// Sleep for the calculated time
	struct timespec ts;
	ts.tv_sec = delay_ms / 1000;
	ts.tv_nsec = (delay_ms % 1000) * 1000000;
	nanosleep (&ts, NULL);
}

#if HAVE_LIBCURL
#include <curl/curl.h>

// Struct to store response data
typedef struct {
	char *data;
	size_t size;
} CurlResponse;

// Callback function for curl to write response data
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	// Check if we've been interrupted
	if (r2ai_http_interrupted) {
		return 0; // Return 0 to abort the transfer
	}

	size_t realsize = size * nmemb;
	CurlResponse *mem = (CurlResponse *)userp;

	char *ptr = realloc (mem->data, mem->size + realsize + 1);
	if (!ptr) {
		R_LOG_ERROR ("Not enough memory for curl response");
		return 0; // Out of memory
	}

	mem->data = ptr;
	memcpy (&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

// Curl progress callback function to handle interrupts
static int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
	// Check if we've been interrupted
	if (r2ai_http_interrupted) {
		return 1; // Return non-zero to abort the transfer
	}
	return 0; // Return 0 to continue
}

static char *curl_http_post(const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	if (!url || !headers || !data || !code) {
		return NULL;
	}

	// Get timeout and retry configuration from config if available
	int timeout = 120; // Default timeout in seconds
	int max_retries = 10; // Default max retries
	int max_backoff = 30; // Default max backoff in seconds

	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}

		max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (max_retries < 0) {
			max_retries = 10; // Use default if invalid
		}

		max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (max_backoff <= 0) {
			max_backoff = 30; // Use default if invalid
		}
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		CURL *curl;
		CURLcode res;
		struct curl_slist *curl_headers = NULL;
		CurlResponse response = { 0 };

		// Initialize response
		response.data = malloc (1);
		if (!response.data) {
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction); // Restore signal handler
			return NULL;
		}
		response.data[0] = '\0';
		response.size = 0;

		curl = curl_easy_init ();
		if (!curl) {
			free (response.data);
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction); // Restore signal handler
			return NULL;
		}

		// Set URL
		curl_easy_setopt (curl, CURLOPT_URL, url);

		// Set POST data
		curl_easy_setopt (curl, CURLOPT_POSTFIELDS, data);

		// Set headers
		for (int i = 0; headers[i] != NULL; i++) {
			curl_headers = curl_slist_append (curl_headers, headers[i]);
		}
		curl_easy_setopt (curl, CURLOPT_HTTPHEADER, curl_headers);

		// Set write callback
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&response);

		// Set progress callback to handle interrupts
		curl_easy_setopt (curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt (curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
		curl_easy_setopt (curl, CURLOPT_XFERINFODATA, NULL);

		// Set timeout options
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connect timeout
		curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)timeout); // Use configured timeout

		// Follow redirects
		curl_easy_setopt (curl, CURLOPT_FOLLOWLOCATION, 1L);

		// Perform the request
		res = curl_easy_perform (curl);

		// Check for interruption
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);
			break; // Exit the retry loop
		}

		// Get response code
		long http_code;
		curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
		*code = (int)http_code;

		// Check for errors
		if (res != CURLE_OK) {
			R_LOG_ERROR ("curl_easy_perform () failed: %s", curl_easy_strerror (res));
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);

			// Retry on network errors
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (http_code == 429 || (http_code >= 500 && http_code < 600)) {
			R_LOG_WARN ("Server returned %d response code", (int)http_code);
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);

			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after rate limiting...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// If we get here, the request was successful
		success = true;
		result = response.data;
		if (rlen) {
			*rlen = response.size;
		}

		// Cleanup
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
	}

	// Restore the original signal handler
	restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}
#endif // HAVE_LIBCURL

#ifdef _WIN32
/**
 * Windows-specific HTTP POST using PowerShell
 */
static char *windows_http_post(const char *url, const char *headers[], const char *data, int *code, int *rlen, int timeout) {
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	r_strbuf_appendf (cmd, "$ProgressPreference='SilentlyContinue';$headers=@{");
	if (headers) {
		for (int i = 0; headers[i]; i++) {
			char *header = strdup (headers[i]);
			char *colon = strchr (header, ':');
			if (colon) {
				*colon = '\0';
				char *key = r_str_trim (header);
				char *value = r_str_trim (colon + 1);
				r_strbuf_appendf (cmd, "'%s'='%s';", key, value);
			}
			free (header);
		}
	}
	r_strbuf_appendf (cmd, "};$body='%s';", data);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Post -Uri '%s' -Headers $headers -Body $body -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			*code = atoi (full_response);
			char *body = newline + 1;
			if (rlen) *rlen = strlen (body);
			char *result = strdup (body);
			free (full_response);
			return result;
		}
		*code = 200;
		if (rlen) *rlen = strlen (full_response);
		return full_response;
	}
	*code = 0;
	return NULL;
}

/**
 * Windows-specific HTTP GET using PowerShell
 */
static char *windows_http_get(const char *url, const char *headers[], int *code, int *rlen, int timeout) {
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	r_strbuf_appendf (cmd, "$ProgressPreference='SilentlyContinue';$headers=@{");
	if (headers) {
		for (int i = 0; headers[i]; i++) {
			char *header = strdup (headers[i]);
			char *colon = strchr (header, ':');
			if (colon) {
				*colon = '\0';
				char *key = r_str_trim (header);
				char *value = r_str_trim (colon + 1);
				r_strbuf_appendf (cmd, "'%s'='%s';", key, value);
			}
			free (header);
		}
	}
	r_strbuf_appendf (cmd, "};");
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Get -Uri '%s' -Headers $headers -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			*code = atoi (full_response);
			char *body = newline + 1;
			if (rlen) *rlen = strlen (body);
			char *result = strdup (body);
			free (full_response);
			return result;
		}
		*code = 200;
		if (rlen) *rlen = strlen (full_response);
		return full_response;
	}
	*code = 0;
	return NULL;
}
#endif

/**
 * Execute curl as a system command, sending data via temporary file
 * On Windows, use PowerShell as fallback when curl is not available
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param data The data to send in the request
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */
static char *system_curl_post_file(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen, bool use_files) {
	if (!url || !headers || !data || !code) {
		return NULL;
	}

	int timeout = r_config_get_i (core->config, "r2ai.http.timeout");
	if (timeout <= 0) {
		timeout = 120; // Use default if invalid
	}

	int max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
	if (max_retries < 0) {
		max_retries = 10; // Use default if invalid
	}

	int max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
	if (max_backoff <= 0) {
		max_backoff = 30; // Use default if invalid
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		// Create a temporary file for the data
		char *temp_file = r_file_temp ("r2ai_data");
		if (!temp_file) {
			R_LOG_ERROR ("Failed to create temporary file for curl data");
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break;
		}

		if (use_files) {
			// Write data to the temporary file
			if (!r_file_dump (temp_file, (const ut8 *)data, strlen (data), 0)) {
				R_LOG_ERROR ("Failed to write data to temporary file");
				free (temp_file);
				if (retry_count < max_retries) {
					retry_count++;
					r2ai_sleep_with_backoff (retry_count, max_backoff);
					continue;
				}
				break;
			}
		}

#ifdef _WIN32
		// On Windows, use PowerShell for HTTP requests
		RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
		r_strbuf_appendf (cmd, "$ProgressPreference = 'SilentlyContinue'; ");
		r_strbuf_appendf (cmd, "$headers = @{");

		// Add headers as PowerShell hashtable
		for (int i = 0; headers[i] != NULL; i++) {
			char *header = strdup (headers[i]);
			char *colon = strchr (header, ':');
			if (colon) {
				*colon = '\0';
				char *key = r_str_trim (header);
				char *value = r_str_trim (colon + 1);
				r_strbuf_appendf (cmd, "'%s'='%s';", key, value);
			}
			free (header);
		}
		r_strbuf_appendf (cmd, "}; ");

		// Add body
		if (use_files) {
			r_strbuf_appendf (cmd, "$body = Get-Content '%s' -Raw; ", temp_file);
		} else {
			char *escaped_data = r_str_replace_all (strdup (data), "'", "''");
			r_strbuf_appendf (cmd, "$body = '%s'; ", escaped_data);
			free (escaped_data);
		}

		r_strbuf_appendf (cmd, "try { $response = Invoke-WebRequest -Method Post -Uri '%s' -Headers $headers -Body $body -TimeoutSec %d; ", url, timeout);
		r_strbuf_appendf (cmd, "Write-Host $response.StatusCode; $response.Content } catch { Write-Host $_.Exception.Response.StatusCode.Value__; $_.Exception.Response.GetResponseStream().ReadToEnd() }\"");

		// Execute the PowerShell command
		char *cmd_str = r_strbuf_drain (cmd);

		R_LOG_DEBUG ("Running PowerShell: %s", cmd_str);
		char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);

		free (cmd_str);
		r_file_rm (temp_file);
		free (temp_file);

		// Parse PowerShell response: first line is status code, rest is body
		if (full_response) {
			char *newline = strchr (full_response, '\n');
			if (newline) {
				*newline = '\0';
				*code = atoi (full_response);
				char *body = newline + 1;
				if (rlen) {
					*rlen = strlen (body);
				}
				result = strdup (body);
			} else {
				*code = 200; // Assume success if no newline
				if (rlen) {
					*rlen = strlen (full_response);
				}
				result = full_response;
			}
			free (full_response);
			success = true;
		} else {
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			*code = 0;
			break;
		}
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

		// Set an alarm to limit the request time
#if R2__UNIX__
		signal (SIGALRM, r2ai_http_sigint_handler);
		alarm (timeout + 10); // Add a little extra for process startup
#endif

		R_LOG_DEBUG ("Running system curl: %s", cmd_str);
		char *response = r_sys_cmd_str (cmd_str, NULL, NULL);

		// Clear the alarm
#if R2__UNIX__
		alarm (0);
#endif

		free (cmd_str);
		r_file_rm (temp_file);
		free (temp_file);

		// Check if we were interrupted
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (response);
			response = NULL;
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);
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
			success = true;
		} else {
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			*code = 0;
			break;
		}
#endif
	}

	// Restore the original signal handler
		restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}

/**
 * Execute curl as a system command for GET requests
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */
static char *system_curl_get(const char *url, const char *headers[], int *code, int *rlen) {
	if (!url || !code) {
		return NULL;
	}

	// Get timeout and retry configuration from config if available
	int timeout = 120; // Default timeout in seconds
	int max_retries = 10; // Default max retries
	int max_backoff = 30; // Default max backoff in seconds

	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}

		max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (max_retries < 0) {
			max_retries = 10; // Use default if invalid
		}

		max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (max_backoff <= 0) {
			max_backoff = 30; // Use default if invalid
		}
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
#ifdef _WIN32
		result = windows_http_get (url, headers, code, rlen, timeout);
		if (result) {
			success = true;
		} else if (retry_count < max_retries) {
			retry_count++;
			R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
			r2ai_sleep_with_backoff (retry_count, max_backoff);
			continue;
		} else {
			*code = 0;
			break;
		}
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
		alarm (timeout + 10); // Add a little extra for process startup
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
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);
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
			success = true;
		} else {
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			*code = 0;
			break;
		}
#endif
	}

	// Restore the original signal handler
	restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}

// Socket implementation with interrupt handling and retry logic
static char *socket_http_post_with_interrupt(const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	// Get timeout and retry configuration from config if available
	int timeout = 120; // Default timeout in seconds
	int max_retries = 10; // Default max retries
	int max_backoff = 30; // Default max backoff in seconds

	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}

		max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (max_retries < 0) {
			max_retries = 10; // Use default if invalid
		}

		max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (max_backoff <= 0) {
			max_backoff = 30; // Use default if invalid
		}
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		// Set an alarm to limit the request time
#if R2__UNIX__
		signal (SIGALRM, r2ai_http_sigint_handler);
		alarm (timeout); // Use configured timeout
#endif

		// Make the request
#if R2_VERSION_NUMBER >= 50909
		result = r_socket_http_post (url, headers, data, code, rlen);
#else
		result = r_socket_http_post (url, data, code, rlen);
#endif

		// Clear the alarm
#if R2__UNIX__
		alarm (0);
#endif

		// Check if we were interrupted
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (result);
			result = NULL;
			break; // Exit the retry loop
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (result && *code) {
			if (*code == 429 || (*code >= 500 && *code < 600)) {
				R_LOG_WARN ("Server returned %d response code", *code);
				free (result);
				result = NULL;

				if (retry_count < max_retries) {
					retry_count++;
					R_LOG_INFO ("Retrying request (%d/%d) after error...", retry_count, max_retries);
					r2ai_sleep_with_backoff (retry_count, max_backoff);
					continue;
				}
				break; // Exit the retry loop after max retries
			}
		}

		// Check for other failures
		if (!result) {
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// If we get here, the request was successful
		success = true;
	}

	// Restore the original signal handler
		restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}

#if HAVE_LIBCURL
static char *curl_http_get(const char *url, const char *headers[], int *code, int *rlen) {
	if (!url || !code) {
		return NULL;
	}

	// Get timeout and retry configuration from config if available
	int timeout = 120; // Default timeout in seconds
	int max_retries = 10; // Default max retries
	int max_backoff = 30; // Default max backoff in seconds

	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}

		max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (max_retries < 0) {
			max_retries = 10; // Use default if invalid
		}

		max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (max_backoff <= 0) {
			max_backoff = 30; // Use default if invalid
		}
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		CURL *curl;
		CURLcode res;
		struct curl_slist *curl_headers = NULL;
		CurlResponse response = { 0 };

		// Initialize response
		response.data = malloc (1);
		if (!response.data) {
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction); // Restore signal handler
			return NULL;
		}
		response.data[0] = '\0';
		response.size = 0;

		curl = curl_easy_init ();
		if (!curl) {
			free (response.data);
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction); // Restore signal handler
			return NULL;
		}

		// Set URL
		curl_easy_setopt (curl, CURLOPT_URL, url);

		// This is a GET request - no POST data
		curl_easy_setopt (curl, CURLOPT_HTTPGET, 1L);

		// Set headers if provided
		if (headers) {
			for (int i = 0; headers[i] != NULL; i++) {
				curl_headers = curl_slist_append (curl_headers, headers[i]);
			}
			curl_easy_setopt (curl, CURLOPT_HTTPHEADER, curl_headers);
		}

		// Set write callback
		curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt (curl, CURLOPT_WRITEDATA, (void *)&response);

		// Set progress callback to handle interrupts
		curl_easy_setopt (curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt (curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
		curl_easy_setopt (curl, CURLOPT_XFERINFODATA, NULL);

		// Set timeout options
		curl_easy_setopt (curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10 seconds connect timeout
		curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)timeout); // Use configured timeout

		// Follow redirects
		curl_easy_setopt (curl, CURLOPT_FOLLOWLOCATION, 1L);

		// Perform the request
		res = curl_easy_perform (curl);

		// Check for interruption
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);
			break; // Exit the retry loop
		}

		// Get response code
		long http_code;
		curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
		*code = (int)http_code;

		// Check for errors
		if (res != CURLE_OK) {
			R_LOG_ERROR ("curl_easy_perform () failed: %s", curl_easy_strerror (res));
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);

			// Retry on network errors
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (http_code == 429 || (http_code >= 500 && http_code < 600)) {
			R_LOG_WARN ("Server returned %d response code", (int)http_code);
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);

			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after rate limiting...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// If we get here, the request was successful
		success = true;
		result = response.data;
		if (rlen) {
			*rlen = response.size;
		}

		// Cleanup
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
	}

	// Restore the original signal handler
		restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}
#endif // HAVE_LIBCURL

// Socket implementation for GET requests
static char *socket_http_get_with_interrupt(const char *url, const char *headers[], int *code, int *rlen) {
	// Get timeout and retry configuration from config if available
	int timeout = 120; // Default timeout in seconds
	int max_retries = 10; // Default max retries
	int max_backoff = 30; // Default max backoff in seconds

	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}

		max_retries = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (max_retries < 0) {
			max_retries = 10; // Use default if invalid
		}

		max_backoff = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (max_backoff <= 0) {
			max_backoff = 30; // Use default if invalid
		}
	}

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local(&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		// Set an alarm to limit the request time
#if R2__UNIX__
		signal (SIGALRM, r2ai_http_sigint_handler);
		alarm (timeout); // Use configured timeout
#endif

		// Make the request - use r_socket_http_get if available
#if R2_VERSION_NUMBER >= 50909
		result = r_socket_http_get (url, headers, code, rlen);
#else
		// For older radare2 versions, we might need to use a different approach
		// or create a custom implementation
		result = NULL;
		*code = 0;
#endif

		// Clear the alarm
#if R2__UNIX__
		alarm (0);
#endif

		// Check if we were interrupted
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (result);
			result = NULL;
			break; // Exit the retry loop
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (result && *code) {
			if (*code == 429 || (*code >= 500 && *code < 600)) {
				R_LOG_WARN ("Server returned %d response code", *code);
				free (result);
				result = NULL;

				if (retry_count < max_retries) {
					retry_count++;
					R_LOG_INFO ("Retrying request (%d/%d) after error...", retry_count, max_retries);
					r2ai_sleep_with_backoff (retry_count, max_backoff);
					continue;
				}
				break; // Exit the retry loop after max retries
			}
		}

		// Check for other failures
		if (!result) {
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff (retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// If we get here, the request was successful
		success = true;
	}

	// Restore the original signal handler
		restore_sigint_handler_local(r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}

R_API char *r2ai_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	const char *backend = "auto";
	bool use_files = false;

	if (core) {
		const char *config_backend = r_config_get (core->config, "r2ai.http.backend");
		if (config_backend) {
			backend = config_backend;
		}
		use_files = r_config_get_b (core->config, "r2ai.http.use_files");
	}
	// Choose implementation based on backend config
	if (!strcmp (backend, "system")) {
		// Always use system curl with files for POST requests
		return system_curl_post_file (core, url, headers, data, code, rlen, use_files);
	} else if (!strcmp (backend, "libcurl")) {
#if USE_LIBCURL && HAVE_LIBCURL
		return curl_http_post (url, headers, data, code, rlen);
#else
		R_LOG_WARN ("LibCurl requested but not available, falling back to socket implementation");
		return socket_http_post_with_interrupt (url, headers, data, code, rlen);
#endif
	} else if (!strcmp (backend, "socket")) {
		return socket_http_post_with_interrupt (url, headers, data, code, rlen);
	} else {
		// Auto-select best available implementation
		if (use_files) {
			// If use_files is true, always use system curl
			return system_curl_post_file (core, url, headers, data, code, rlen, use_files);
		} else {
#if USE_LIBCURL && HAVE_LIBCURL
			return curl_http_post (url, headers, data, code, rlen);
#else
#if USE_R2_CURL
			r_sys_setenv ("R2_CURL", "1");
#endif
			return socket_http_post_with_interrupt (url, headers, data, code, rlen);
#endif
		}
	}
}

R_API char *r2ai_http_get(const char *url, const char *headers[], int *code, int *rlen) {
	RCore *core = r_cons_singleton ()->user;
	const char *backend = "auto";

	if (core) {
		backend = r_config_get (core->config, "r2ai.http.backend");
	}

	// Choose implementation based on backend config
	if (!strcmp (backend, "system")) {
		// Use system curl for GET requests
		return system_curl_get (url, headers, code, rlen);
	} else if (!strcmp (backend, "libcurl")) {
#if USE_LIBCURL && HAVE_LIBCURL
		return curl_http_get (url, headers, code, rlen);
#else
		R_LOG_WARN ("LibCurl requested but not available, falling back to socket implementation");
		return socket_http_get_with_interrupt (url, headers, code, rlen);
#endif
	} else if (!strcmp (backend, "socket")) {
		return socket_http_get_with_interrupt (url, headers, code, rlen);
	} else {
		// Auto-select best available implementation
#if USE_LIBCURL && HAVE_LIBCURL
		return curl_http_get (url, headers, code, rlen);
#else
#if USE_R2_CURL
		r_sys_setenv ("R2_CURL", "1");
#endif
		return socket_http_get_with_interrupt (url, headers, code, rlen);
#endif
	}
}
