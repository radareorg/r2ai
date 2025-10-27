#if R2__WINDOWS__

// Helper to escape single quotes for PowerShell single-quoted strings
static char *escape_single_quotes(const char *str) {
	if (!str) {
		return NULL;
	}
	size_t len = strlen (str);
	size_t count = 0;
	for (size_t i = 0; i < len; i++) {
		if (str[i] == '\'') {
			count++;
		}
	}
	if (count == 0) {
		return strdup (str);
	}
	char *escaped = malloc (len + count + 1);
	if (!escaped) {
		return NULL;
	}
	size_t j = 0;
	for (size_t i = 0; i < len; i++) {
		if (str[i] == '\'') {
			escaped[j++] = '\'';
			escaped[j++] = '\'';
		} else {
			escaped[j++] = str[i];
		}
	}
	escaped[j] = '\0';
	return escaped;
}

// Helper to append headers to PowerShell command
static void append_headers_to_cmd(RStrBuf *cmd, const char *const *headers) {
	r_strbuf_appendf (cmd, "$headers=@{");
	if (headers) {
		for (int i = 0; headers[i]; i++) {
			char *header = strdup (headers[i]);
			char *colon = strchr (header, ':');
			if (colon) {
				*colon = '\0';
				char *key = r_str_trim_dup (header);
				char *value = r_str_trim_dup (colon + 1);
				char *escaped_key = escape_single_quotes (key);
				char *escaped_value = escape_single_quotes (value);
				r_strbuf_appendf (cmd, "'%s'='%s';", escaped_key, escaped_value);
				free (escaped_key);
				free (escaped_value);
				free (key);
				free (value);
			}
			free (header);
		}
	}
	r_strbuf_appendf (cmd, "};");
}

// Helper to parse PowerShell response
static HttpResponse parse_powershell_response(char *full_response) {
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			int code = atoi (full_response);
			char *body = newline + 1;
			char *body_copy = strdup (body);
			size_t length = strlen (body);
			free (full_response);
			return (HttpResponse){ .body = body_copy, .code = code, .length = length };
		} else {
			return (HttpResponse){ .body = full_response, .code = 200, .length = strlen (full_response) };
		}
	}
	return (HttpResponse){ .code = -1 };
}
/**
 * Windows-specific HTTP POST using PowerShell
 */
HttpResponse windows_http_post(const HTTPRequest *request) {
	const char *url = request->url;
	const char *const *headers = request->headers;
	const char *data = request->data;
	int timeout = request->config.timeout;
	char *escaped_url = escape_single_quotes (url);
	char *escaped_data = escape_single_quotes (data);
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "$body='%s';", escaped_data);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Post -Uri '%s' -Headers $headers -Body $body -TimeoutSec %d;", escaped_url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	R_LOG_DEBUG ("Running PowerShell: %s", cmd_str);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	return parse_powershell_response (full_response);
}

/**
 * Windows-specific HTTP GET using PowerShell
 */
HttpResponse windows_http_get(const HTTPRequest *request) {
	const char *url = request->url;
	const char *const *headers = request->headers;
	int timeout = request->config.timeout;
	char *escaped_url = escape_single_quotes (url);
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Get -Uri '%s' -Headers $headers -TimeoutSec %d;", escaped_url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	R_LOG_DEBUG ("Running PowerShell: %s", cmd_str);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	return parse_powershell_response (full_response);
}
#endif
