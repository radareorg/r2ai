#include "r2ai.h"
#include <signal.h>

// Global flag for tracking interrupt status
static volatile sig_atomic_t r2ai_http_interrupted = 0;

// Signal handler for SIGINT
static void r2ai_http_sigint_handler (int sig) {
	r2ai_http_interrupted = 1;
}

#if HAVE_LIBCURL
#include <curl/curl.h>

// Struct to store response data
typedef struct {
	char *data;
	size_t size;
} CurlResponse;

// Callback function for curl to write response data
static size_t write_callback (void *contents, size_t size, size_t nmemb, void *userp) {
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
static int progress_callback (void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
	// Check if we've been interrupted
	if (r2ai_http_interrupted) {
		return 1; // Return non-zero to abort the transfer
	}
	return 0; // Return 0 to continue
}

static char *curl_http_post (const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	if (!url || !headers || !data || !code) {
		return NULL;
	}

	// Get timeout from config if available
	int timeout = 120; // Default timeout in seconds
	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}
	}

	// Install signal handler for interruption
	struct sigaction new_action, old_action;
	new_action.sa_handler = r2ai_http_sigint_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, &new_action, &old_action);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	CURL *curl;
	CURLcode res;
	struct curl_slist *curl_headers = NULL;
	CurlResponse response = { 0 };

	// Initialize response
	response.data = malloc (1);
	if (!response.data) {
		sigaction (SIGINT, &old_action, NULL); // Restore signal handler
		return NULL;
	}
	response.data[0] = '\0';
	response.size = 0;

	curl = curl_easy_init ();
	if (!curl) {
		free (response.data);
		sigaction (SIGINT, &old_action, NULL); // Restore signal handler
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

	// Restore the original signal handler
	sigaction (SIGINT, &old_action, NULL);

	// Check for interruption
	if (r2ai_http_interrupted) {
		R_LOG_INFO ("HTTP request was interrupted by user");
		free (response.data);
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
		return NULL;
	}

	// Check for errors
	if (res != CURLE_OK) {
		R_LOG_ERROR ("curl_easy_perform() failed: %s", curl_easy_strerror (res));
		free (response.data);
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
		return NULL;
	}

	// Get response code
	long http_code;
	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
	*code = (int)http_code;

	// Cleanup
	curl_slist_free_all (curl_headers);
	curl_easy_cleanup (curl);

	return response.data;
}
#endif // HAVE_LIBCURL

// Socket implementation with interrupt handling
static char *socket_http_post_with_interrupt (const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	// Get timeout from config if available
	int timeout = 120; // Default timeout in seconds
	RCore *core = r_cons_singleton ()->user;
	if (core) {
		timeout = r_config_get_i (core->config, "r2ai.http.timeout");
		if (timeout <= 0) {
			timeout = 120; // Use default if invalid
		}
	}

	// Install signal handler for interruption
	struct sigaction new_action, old_action;
	new_action.sa_handler = r2ai_http_sigint_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, &new_action, &old_action);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Set an alarm to limit the request time
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (timeout); // Use configured timeout

	// Make the request
	char *result = r_socket_http_post (url, headers, data, code, rlen);

	// Clear the alarm
	alarm (0);

	// Restore the original signal handler
	sigaction (SIGINT, &old_action, NULL);

	// Check if we were interrupted
	if (r2ai_http_interrupted) {
		R_LOG_INFO ("HTTP request was interrupted by user");
		free (result);
		return NULL;
	}

	return result;
}

R_API char *r2ai_http_post (const char *url, const char *headers[], const char *data, int *code, int *rlen) {
#if HAVE_LIBCURL
	// Get the current core instance
	RCore *core = r_cons_singleton ()->user;
	if (core) {
		// Check if config exists and if curl is preferred
		const char *backend = r_config_get (core->config, "r2ai.http.backend");
		if (backend && !strcmp (backend, "curl")) {
			R_LOG_INFO ("Using libcurl for HTTP request");
			return curl_http_post (url, headers, data, code, rlen);
		} else {
			R_LOG_INFO ("Using r_socket for HTTP request (configured)");
			return socket_http_post_with_interrupt (url, headers, data, code, rlen);
		}
	}

	// Fallback to socket if config can't be accessed
	R_LOG_INFO ("Using r_socket for HTTP request (fallback)");
	return socket_http_post_with_interrupt (url, headers, data, code, rlen);
#else
	return socket_http_post_with_interrupt (url, headers, data, code, rlen);
#endif
}

R_API bool r2ai_http_has_curl (void) {
#if HAVE_LIBCURL
	return true;
#else
	return false;
#endif
}