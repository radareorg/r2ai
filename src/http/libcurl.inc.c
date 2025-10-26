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
	return r2ai_http_interrupted? 1: 0;
}

HttpResponse curl_http_get(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	if (!request->url) {
		return error;
	}

	CURL *curl;
	CURLcode res;
	struct curl_slist *curl_headers = NULL;
	CurlResponse response = { 0 };

	// Initialize response
	response.data = malloc (1);
	if (!response.data) {
		return error;
	}
	response.data[0] = '\0';
	response.size = 0;

	curl = curl_easy_init ();
	if (!curl) {
		free (response.data);
		return error;
	}

	// Set URL
	curl_easy_setopt (curl, CURLOPT_URL, request->url);

	// This is a GET request - no POST data
	curl_easy_setopt (curl, CURLOPT_HTTPGET, 1L);

	// Set headers if provided
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			curl_headers = curl_slist_append (curl_headers, request->headers[i]);
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
	curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)request->config.timeout); // Use configured timeout

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
		return error;
	}

	// Get response code
	long http_code;
	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

	// Check for errors
	if (res != CURLE_OK) {
		R_LOG_ERROR ("curl_easy_perform () failed: %s", curl_easy_strerror (res));
		free (response.data);
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
		return error;
	}

	// If we get here, the request was successful
	// Cleanup
	curl_slist_free_all (curl_headers);
	curl_easy_cleanup (curl);

	return (HttpResponse){ .body = response.data, .code = (int)http_code, .length = response.size };
}

HttpResponse curl_http_post(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	if (!request->url || !request->data) {
		return error;
	}

	CURL *curl;
	CURLcode res;
	struct curl_slist *curl_headers = NULL;
	CurlResponse response = { 0 };

	// Initialize response
	response.data = malloc (1);
	if (!response.data) {
		return error;
	}
	response.data[0] = '\0';
	response.size = 0;

	curl = curl_easy_init ();
	if (!curl) {
		free (response.data);
		return error;
	}

	// Set URL
	curl_easy_setopt (curl, CURLOPT_URL, request->url);

	// This is a POST request
	curl_easy_setopt (curl, CURLOPT_POST, 1L);
	curl_easy_setopt (curl, CURLOPT_POSTFIELDS, request->data);
	curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, (long)strlen (request->data));

	// Set headers if provided
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			curl_headers = curl_slist_append (curl_headers, request->headers[i]);
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
	curl_easy_setopt (curl, CURLOPT_TIMEOUT, (long)request->config.timeout); // Use configured timeout

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
		return error;
	}

	// Get response code
	long http_code;
	curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);

	// Check for errors
	if (res != CURLE_OK) {
		R_LOG_ERROR ("curl_easy_perform () failed: %s", curl_easy_strerror (res));
		free (response.data);
		curl_slist_free_all (curl_headers);
		curl_easy_cleanup (curl);
		return error;
	}

	// If we get here, the request was successful
	// Cleanup
	curl_slist_free_all (curl_headers);
	curl_easy_cleanup (curl);

	return (HttpResponse){ .body = response.data, .code = (int)http_code, .length = response.size };
}
#endif // HAVE_LIBCURL
