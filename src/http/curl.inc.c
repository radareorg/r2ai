static HttpResponse build_and_execute_curl(const char *cmd_start, const HTTPRequest *request, const char *input_data) {
	HttpResponse error = { .code = -1 };
	int timeout = request->config.timeout;
	if (!request->url) {
		return error;
	}

	// Compose curl command
	RStrBuf *cmd = r_strbuf_new (cmd_start);

	// Add timeout
	r_strbuf_appendf (cmd, " --connect-timeout %d --max-time %d", 10, timeout);

	// Add headers
	if (request->headers) {
		for (int i = 0; request->headers[i] != NULL; i++) {
			r_strbuf_appendf (cmd, " -H '%s'", request->headers[i]);
		}
	}
	r_strbuf_appendf (cmd, " -w '\\n%%{http_code}' '%s'", request->url);
	char *cmd_str = r_strbuf_drain (cmd);
	R_LOG_DEBUG ("Running system curl: %s", cmd_str);
	char *response = r_sys_cmd_str (cmd_str, input_data, NULL);

	free (cmd_str);

	if (!response) {
		return error;
	}

	// Parse the response: body\ncode
	char *last_nl = (char *)r_str_rchr (response, NULL, '\n');
	int code = -1;
	char *body = response;
	if (last_nl) {
		*last_nl = '\0';
		code = atoi (last_nl + 1);
		if (code == 0) {
			code = -1; // Invalid code
		}
	} else {
		// No newline, assume 200 if response
		code = 200;
	}

	return (HttpResponse){ .body = body, .code = code, .length = strlen (body) };
}

HttpResponse system_curl_get(const HTTPRequest *request) {
	R_LOG_DEBUG ("Using system curl GET");
	return build_and_execute_curl ("curl -s", request, NULL);
}

HttpResponse system_curl_post(const HTTPRequest *request) {
	HttpResponse error = { .code = -1 };
	if (!request->url || !request->data) {
		return error;
	}

	R_LOG_DEBUG ("Using system curl POST without files");
	HttpResponse res = build_and_execute_curl ("curl -s -X POST -d @-", request, request->data);
	return res;
}
