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

// HTTP configuration structure
typedef struct {
	int timeout;
	int max_retries;
	int max_backoff;
} R2AI_HttpConfig;

// Global flag for tracking interrupt status
static volatile sig_atomic_t r2ai_http_interrupted = 0;

// Helper function to get HTTP configuration with defaults
static R2AI_HttpConfig get_http_config(RCore *core) {
	R2AI_HttpConfig config = { 120, 10, 30 };
	if (core) {
		int t = r_config_get_i (core->config, "r2ai.http.timeout");
		if (t > 0) {
			config.timeout = t;
		}
		int mr = r_config_get_i (core->config, "r2ai.http.max_retries");
		if (mr >= 0) {
			config.max_retries = mr;
		}
		int mb = r_config_get_i (core->config, "r2ai.http.max_backoff");
		if (mb > 0) {
			config.max_backoff = mb;
		}
	}
	return config;
}

// Signal handler for SIGINT
static void r2ai_http_sigint_handler(int sig) {
	(void)sig;
	r2ai_http_interrupted = 1;
}

/*
 * Portable install/restore helpers for SIGINT handler.
 * Some platforms may not have struct sigaction available; use signal ()
 * as a fallback. We allocate storage for the old handler when
 * sigaction is available so the restore function can restore it later.
 */
static void install_sigint_handler_local(void **out_old, int *out_old_is_sigaction) {
	void (*old) (int) = signal (SIGINT, r2ai_http_sigint_handler);
	*out_old = (void *)old;
	*out_old_is_sigaction = 0;
}

static void restore_sigint_handler_local(void *old, int old_is_sigaction) {
	(void)old_is_sigaction;
	signal (SIGINT, (void (*) (int))old);
}

// Function pointer type for HTTP request implementations
typedef char *(*HttpRequestFunc)(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);

// Simple retry sleep
static void sleep_retry(int retry_count, int max_sleep_seconds) {
	int delay_seconds = retry_count + 1; // sleep 1, 2, 3, ... seconds
	if (delay_seconds > max_sleep_seconds) {
		delay_seconds = max_sleep_seconds;
	}
	r_sys_sleep (delay_seconds);
}

// Generic HTTP request with retry logic
static char *r2ai_http_request_with_retry(RCore *core, HttpRequestFunc func, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	R2AI_HttpConfig config = get_http_config (core);

	// Install signal handler for interruption (portable)
	void *r2ai_old_sig = NULL;
	int r2ai_old_is_sigaction = 0;
	install_sigint_handler_local (&r2ai_old_sig, &r2ai_old_is_sigaction);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= config.max_retries && !r2ai_http_interrupted) {
		result = func (core, url, headers, data, code, rlen);

		// Check if we were interrupted
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			free (result);
			result = NULL;
			break; // Exit the retry loop
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (result && code && *code) {
			if (*code == 429 || (*code >= 500 && *code < 600)) {
				R_LOG_WARN ("Server returned %d response code", *code);
				free (result);
				result = NULL;

				if (retry_count < config.max_retries) {
					retry_count++;
					R_LOG_INFO ("Retrying request (%d/%d) after error...", retry_count, config.max_retries);
					sleep_retry (retry_count, config.max_backoff);
					continue;
				}
				break; // Exit the retry loop after max retries
			}
		}

		// Check for other failures
		if (!result) {
			if (retry_count < config.max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, config.max_retries);
				sleep_retry (retry_count, config.max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}

		// If we get here, the request was successful
		success = true;
	}

	// Restore the original signal handler
	restore_sigint_handler_local (r2ai_old_sig, r2ai_old_is_sigaction);

	return result;
}

// Forward declarations
static char *socket_http_post_with_interrupt(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
static char *socket_http_get_with_interrupt(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);

// Forward declarations for functions defined in include files
char *curl_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
char *curl_http_get(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
char *windows_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
char *windows_http_get(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
char *system_curl_post_file(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);
char *system_curl_get(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen);

#include "http_libcurl.inc.c"

#include "http_pwsh.inc.c"

#include "http_curl.inc.c"



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

/**
 * Execute curl as a system command for GET requests
 *
 * @param url The URL to send the request to
 * @param headers Array of headers, NULL terminated
 * @param code Pointer to store the response code
 * @param rlen Pointer to store the response length
 * @return Response body as string (must be freed by caller) or NULL on error
 */

// Socket implementation with interrupt handling and retry logic
static char *socket_http_post_with_interrupt(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	R2AI_HttpConfig config = get_http_config (core);

	// Set an alarm to limit the request time
#if R2__UNIX__
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (config.timeout); // Use configured timeout
#endif

	// Make the request
	char *result = r_socket_http_post (url, headers, data, code, rlen);

	// Clear the alarm
#if R2__UNIX__
	alarm (0);
#endif

	// Check if we were interrupted
	if (r2ai_http_interrupted) {
		R_LOG_DEBUG ("HTTP request was interrupted by user");
		free (result);
		result = NULL;
	}

	return result;
}

// Socket implementation for GET requests
static char *socket_http_get_with_interrupt(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	R2AI_HttpConfig config = get_http_config (core);

	// Set an alarm to limit the request time
#if R2__UNIX__
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (config.timeout); // Use configured timeout
#endif
	// Make the request - use r_socket_http_get if available
	char *result = r_socket_http_get (url, headers, code, rlen);
#if R2__UNIX__
	alarm (0);
#endif

	// Check if we were interrupted
	if (r2ai_http_interrupted) {
		R_LOG_DEBUG ("HTTP request was interrupted by user");
		free (result);
		result = NULL;
	}

	return result;
}

// Generic HTTP request function that handles backend selection
static char *r2ai_http_request(const char *method, RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	const char *backend = "auto";
	bool use_files = false;
	bool is_post = (data != NULL);
	HttpRequestFunc func = NULL;

	if (core) {
		const char *config_backend = r_config_get (core->config, "r2ai.http.backend");
		if (config_backend) {
			backend = config_backend;
		}
		if (is_post) {
			use_files = r_config_get_b (core->config, "r2ai.http.use_files");
		}
	}

	// Select the appropriate backend function
	if (!strcmp (backend, "system")) {
		func = is_post? system_curl_post_file: system_curl_get;
	} else if (!strcmp (backend, "libcurl")) {
#if USE_LIBCURL && HAVE_LIBCURL
		func = is_post? curl_http_post: curl_http_get;
#else
		R_LOG_WARN ("LibCurl requested but not available, falling back to socket implementation");
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
#endif
	} else if (!strcmp (backend, "socket")) {
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
	} else {
		// Auto backend selection
		if (is_post && use_files) {
			// Special case: use system curl with files
			return r2ai_http_request_with_retry (core, system_curl_post_file, url, headers, data, code, rlen);
		}
#if USE_LIBCURL && HAVE_LIBCURL
		func = is_post? curl_http_post: curl_http_get;
#elif defined(_WIN32)
		func = is_post? windows_http_post: windows_http_get;
#else
#if USE_R2_CURL
		r_sys_setenv ("R2_CURL", "1");
#endif
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
#endif
	}

	if (func) {
		return r2ai_http_request_with_retry (core, func, url, headers, data, code, rlen);
	}
	R_LOG_ERROR ("Cannot find a valid http backend");
	return NULL;
}

R_API char *r2ai_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	return r2ai_http_request ("POST", core, url, headers, data, code, rlen);
}

R_API char *r2ai_http_get(RCore *core, const char *url, const char *headers[], int *code, int *rlen) {
	return r2ai_http_request ("GET", core, url, headers, NULL, code, rlen);
}
