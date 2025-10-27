extern volatile sig_atomic_t r2ai_http_interrupted;
extern void r2ai_http_sigint_handler(int sig);


// Socket implementation with interrupt handling and retry logic
static HttpResponse socket_http_post_with_interrupt(const HTTPRequest *request) {
#if R2__WINDOWS__
	r_sys_setenv ("R2_CURL", "1");
#endif
#if R2__UNIX__
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (request->config.timeout); // Use configured timeout
#endif
	int code = 0;
	int rlen = 0;
	char *result = r_socket_http_post (request->url, (const char **)request->headers, request->data, &code, &rlen);
#if R2__UNIX__
	alarm (0);
#endif
	if (r2ai_http_interrupted) {
		R_LOG_DEBUG ("HTTP request was interrupted by user");
		free (result);
		return (HttpResponse){ .body = NULL, .code = -1, .length = 0 };
	}
	return (HttpResponse){ .body = result, .code = code, .length = rlen };
}

// Socket implementation for GET requests
static HttpResponse socket_http_get_with_interrupt(const HTTPRequest *request) {
#if R2__WINDOWS__
	r_sys_setenv ("R2_CURL", "1");
#endif
#if R2__UNIX__
	signal (SIGALRM, r2ai_http_sigint_handler);
	alarm (request->config.timeout); // Use configured timeout
#endif
	// Make the request - use r_socket_http_get if available
	int code = 0;
	int rlen = 0;
	char *result = r_socket_http_get (request->url, (const char **)request->headers, &code, &rlen);
#if R2__UNIX__
	alarm (0);
#endif
	if (r2ai_http_interrupted) {
		R_LOG_DEBUG ("HTTP request was interrupted by user");
		free (result);
		return (HttpResponse){ .body = NULL, .code = -1, .length = 0 };
	}
	return (HttpResponse){ .body = result, .code = code, .length = rlen };
}
