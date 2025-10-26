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

char *curl_http_post(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	if (!url || !headers || !data || !code) {
		return NULL;
	}

	R2AI_HttpConfig config = get_http_config (core);

	CURL *curl;
	CURLcode res;
	struct curl_slist *curl_headers = NULL;
	CurlResponse response = { 0 };

	// Initialize response
	response.data = malloc (1);
	if (!response.data) {
		return NULL;
	}
	response.data[0] = '\0';
	response.size = 0;

	curl = curl_easy_init ();
	if (!curl) {
		free (response.data);
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
	curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)config.timeout); // Use configured timeout

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
		return NULL;
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
		return NULL;
	}

	// If we get here, the request was successful
	char *result = response.data;
	if (rlen) {
		*rlen = response.size;
	}

	// Cleanup
	curl_slist_free_all (curl_headers);
	curl_easy_cleanup (curl);

	return result;
}

char *curl_http_get(RCore *core, const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	if (!url || !code) {
		return NULL;
	}

	R2AI_HttpConfig config = get_http_config (core);

	CURL *curl;
	CURLcode res;
	struct curl_slist *curl_headers = NULL;
	CurlResponse response = { 0 };

	// Initialize response
	response.data = malloc (1);
	if (!response.data) {
		return NULL;
	}
	response.data[0] = '\0';
	response.size = 0;

	curl = curl_easy_init ();
	if (!curl) {
		free (response.data);
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
	curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)config.timeout); // Use configured timeout

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
		return NULL;
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
		return NULL;
	}

	// If we get here, the request was successful
	char *result = response.data;
	if (rlen) {
		*rlen = response.size;
	}

	// Cleanup
	curl_slist_free_all (curl_headers);
	curl_easy_cleanup (curl);

	return result;
}
#endif // HAVE_LIBCURL