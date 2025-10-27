#include "r2ai.h"
#include <signal.h>
#include <time.h>

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

#ifndef _WIN32
// Signal handler for timeout (SIGALRM)
static void r2ai_http_sigint_handler(int sig) {
	if (sig == SIGALRM) {
		r2ai_http_interrupted = 1;
	}
}
#endif

// Portable break callback for r_cons_break (handles SIGINT)
static void r2ai_http_break_callback(void *user) {
	(void)user;
	r2ai_http_interrupted = 1;
}

// Function pointer type for HTTP request implementations
typedef HttpResponse(*HttpRequestFunc)(const HTTPRequest *request);

// Simple retry sleep
static void sleep_retry(int retry_count, int max_sleep_seconds) {
	int delay_seconds = retry_count + 1; // sleep 1, 2, 3, ... seconds
	if (delay_seconds > max_sleep_seconds) {
		delay_seconds = max_sleep_seconds;
	}
	r_sys_sleep (delay_seconds);
}

// Generic HTTP request with retry logic
static HttpResponse r2ai_http_request_with_retry(HttpRequestFunc func, const HTTPRequest *request, RCore *core) {
	// Install portable break handler for interruption
	if (core && core->cons) {
		r_cons_break_push (core->cons, r2ai_http_break_callback, NULL);
	}

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	HttpResponse result = { 0 };
	int retry_count = 0;
	bool success = false;

	while (!success && retry_count <= request->config.max_retries && !r2ai_http_interrupted) {
		result = func (request);

		// Check if we were interrupted
		if (r2ai_http_interrupted) {
			R_LOG_DEBUG ("HTTP request was interrupted by user");
			if (result.body) {
				free (result.body);
			}
			result.body = NULL;
			result.code = -1;
			break; // Exit the retry loop
		}

		// Check for rate limiting or server errors (429, 500, 502, 503, 504)
		if (result.code > 0) {
			if (result.code == 429 || (result.code >= 500 && result.code < 600)) {
				R_LOG_WARN ("Server returned %d response code", result.code);
				free (result.body);
				result.body = NULL;
				result.code = 0;

				if (retry_count < request->config.max_retries) {
					retry_count++;
					R_LOG_INFO ("Retrying request (%d/%d) after error...", retry_count, request->config.max_retries);
					sleep_retry (retry_count, request->config.max_backoff);
					continue;
				}
				result.code = -1;
				break; // Exit the retry loop after max retries
			}
		}

		// Check for other failures
		if (result.code <= 0 || !result.body) {
			if (result.body) {
				free (result.body);
			}
			result.body = NULL;
			result.code = -1;
			if (retry_count < request->config.max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, request->config.max_retries);
				sleep_retry (retry_count, request->config.max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}
		success = true;
	}

	// Restore the original break handler
	if (core && core->cons) {
		r_cons_break_pop (core->cons);
	}

	return result;
}

#include "http/libcurl.inc.c"
#include "http/pwsh.inc.c"
#include "http/curl.inc.c"
#include "http/r2.inc.c"

static HttpRequestFunc select_backend(const char *backend, bool is_post) {
	HttpRequestFunc func = NULL;
	// Select the appropriate backend function
	if (!strcmp (backend, "auto")) {
		// Auto-select the best available backend
#if defined(_WIN32)
		backend = "pwsh";
#elif USE_LIBCURL && HAVE_LIBCURL
		backend = "libcurl";
#else
		backend = "system";
#endif
		R_LOG_DEBUG ("Auto-selected %s backend", backend);
	}
	if (!strcmp (backend, "system") || !strcmp (backend, "curl")) {
		func = is_post? system_curl_post: system_curl_get;
	} else if (!strcmp (backend, "libcurl")) {
#if USE_LIBCURL && HAVE_LIBCURL
		func = is_post? curl_http_post: curl_http_get;
#else
		R_LOG_WARN ("LibCurl requested but not available, falling back to socket implementation");
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
#endif
	} else if (!strcmp (backend, "socket")) {
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
	} else if (!strcmp (backend, "pwsh") || !strcmp (backend, "powershell")) {
#if defined(_WIN32)
		func = is_post? windows_http_post: windows_http_get;
#else
		R_LOG_WARN ("powershell is only available on Windows");
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
#endif
	} else if (!strcmp (backend, "r2curl")) {
		r_sys_setenv ("R2_CURL", "1");
		func = is_post? socket_http_post_with_interrupt: socket_http_get_with_interrupt;
	}
	return func;
}

// Generic HTTP request function that handles backend selection
static HttpResponse r2ai_http_request(const char *method, RCore *core, const char *url, const char *headers[], const char *data) {
	(void)method;
	bool is_post = (data != NULL);

	HTTPRequest request = {
		.config = get_http_config (core),
		.url = url,
		.data = data,
		.headers = headers
	};

	const char *backend = r_config_get (core->config, "r2ai.http.backend");
	HttpRequestFunc func = select_backend (backend, is_post);
	if (func) {
		return r2ai_http_request_with_retry (func, &request, core);
	}
	R_LOG_ERROR ("Cannot find a valid http backend");
	return (HttpResponse){ .body = NULL, .code = -1, .length = 0 };
}

R_API char *r2ai_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	HttpResponse response = r2ai_http_request ("POST", core, url, headers, data);
	if (response.code <= 0) {
		if (response.body) {
			free (response.body);
		}
		if (code) {
			*code = response.code;
		}
		return NULL;
	}
	if (code) {
		*code = response.code;
	}
	if (rlen) {
		*rlen = response.length;
	}
	return response.body;
}

R_API char *r2ai_http_get(RCore *core, const char *url, const char *headers[], int *code, int *rlen) {
	HttpResponse response = r2ai_http_request ("GET", core, url, headers, NULL);
	if (response.code <= 0) {
		if (response.body) {
			R_FREE (response.body);
		}
		if (code) {
			*code = response.code;
		}
		return NULL;
	}
	if (code) {
		*code = response.code;
	}
	if (rlen) {
		*rlen = response.length;
	}
	return response.body;
}
