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
static void r2ai_http_sigint_handler (int sig) {
	r2ai_http_interrupted = 1;
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
		srand(time(NULL) + retry_count);
		delay_ms += (rand() % (jitter * 2)) - jitter;
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
	nanosleep(&ts, NULL);
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

	// Install signal handler for interruption
	struct sigaction new_action, old_action;
	new_action.sa_handler = r2ai_http_sigint_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, &new_action, &old_action);

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
				r2ai_sleep_with_backoff(retry_count, max_backoff);
				continue;
			}
			sigaction (SIGINT, &old_action, NULL); // Restore signal handler
			return NULL;
		}
		response.data[0] = '\0';
		response.size = 0;

		curl = curl_easy_init ();
		if (!curl) {
			free (response.data);
			if (retry_count < max_retries) {
				retry_count++;
				r2ai_sleep_with_backoff(retry_count, max_backoff);
				continue;
			}
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
			R_LOG_ERROR ("curl_easy_perform() failed: %s", curl_easy_strerror (res));
			free (response.data);
			curl_slist_free_all (curl_headers);
			curl_easy_cleanup (curl);
			
			// Retry on network errors
			if (retry_count < max_retries) {
				retry_count++;
				R_LOG_INFO ("Retrying request (%d/%d) after failure...", retry_count, max_retries);
				r2ai_sleep_with_backoff(retry_count, max_backoff);
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
				r2ai_sleep_with_backoff(retry_count, max_backoff);
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
	sigaction (SIGINT, &old_action, NULL);
	
	return result;
}
#endif // HAVE_LIBCURL

// Socket implementation with interrupt handling and retry logic
static char *socket_http_post_with_interrupt (const char *url, const char *headers[], const char *data, int *code, int *rlen) {
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

	// Install signal handler for interruption
	struct sigaction new_action, old_action;
	new_action.sa_handler = r2ai_http_sigint_handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction (SIGINT, &new_action, &old_action);

	// Reset interrupt flag
	r2ai_http_interrupted = 0;

	// Retry loop
	char *result = NULL;
	int retry_count = 0;
	bool success = false;
	
	while (!success && retry_count <= max_retries && !r2ai_http_interrupted) {
		// Set an alarm to limit the request time
		signal (SIGALRM, r2ai_http_sigint_handler);
		alarm (timeout); // Use configured timeout

		// Make the request
#if R2_VERSION_NUMBER >= 50909
		result = r_socket_http_post (url, headers, data, code, rlen);
#else
		result = r_socket_http_post (url, data, code, rlen);
#endif

		// Clear the alarm
		alarm (0);

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
					r2ai_sleep_with_backoff(retry_count, max_backoff);
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
				r2ai_sleep_with_backoff(retry_count, max_backoff);
				continue;
			}
			break; // Exit the retry loop after max retries
		}
		
		// If we get here, the request was successful
		success = true;
	}

	// Restore the original signal handler
	sigaction (SIGINT, &old_action, NULL);

	return result;
}

R_API char *r2ai_http_post (const char *url, const char *headers[], const char *data, int *code, int *rlen) {
#if USE_LIBCURL && HAVE_LIBCURL
	return curl_http_post (url, headers, data, code, rlen);
#else
#if USE_R2_CURL
	r_sys_setenv ("R2_CURL", "1");
#endif
	return socket_http_post_with_interrupt (url, headers, data, code, rlen);
#endif
}