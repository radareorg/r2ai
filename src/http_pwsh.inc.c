#ifdef _WIN32

// Helper to append headers to PowerShell command
static void append_headers_to_cmd(RStrBuf *cmd, const char *headers[]) {
	r_strbuf_appendf (cmd, "$ProgressPreference='SilentlyContinue';$headers=@{");
	if (headers) {
		for (int i = 0; headers[i]; i++) {
			char *header = strdup (headers[i]);
			char *colon = strchr (header, ':');
			if (colon) {
				*colon = '\0';
				char *key = r_str_trim_dup (header);
				char *value = r_str_trim_dup (colon + 1);
				r_strbuf_appendf (cmd, "'%s'='%s';", key, value);
				free (key);
				free (value);
			}
			free (header);
		}
	}
	r_strbuf_appendf (cmd, "};");
}
/**
 * Windows-specific HTTP POST using PowerShell
 */
HttpResponse *windows_http_post(const char *url, const char *headers[], const char *data, int timeout) {
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "$body='%s';", data);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Post -Uri '%s' -Headers $headers -Body $body -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	HttpResponse *result = NULL;
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			int code = atoi (full_response);
			char *body = newline + 1;
			result = R_NEW0 (HttpResponse);
			if (result) {
				result->body = strdup (body);
				result->code = code;
				result->length = strlen (body);
			}
		} else {
			result = R_NEW0 (HttpResponse);
			if (result) {
				result->body = full_response;
				result->code = 200;
				result->length = strlen (full_response);
				full_response = NULL; // Don't free it since we're using it
			}
		}
	}
	free (full_response);
	return result;
}

/**
 * Windows-specific HTTP GET using PowerShell
 */
HttpResponse *windows_http_get(const char *url, const char *headers[], int timeout) {

	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Get -Uri '%s' -Headers $headers -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	HttpResponse *result = NULL;
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			int code = atoi (full_response);
			char *body = newline + 1;
			result = R_NEW0 (HttpResponse);
			if (result) {
				result->body = strdup (body);
				result->code = code;
				result->length = strlen (body);
			}
		} else {
			result = R_NEW0 (HttpResponse);
			if (result) {
				result->body = full_response;
				result->code = 200;
				result->length = strlen (full_response);
				full_response = NULL; // Don't free it since we're using it
			}
		}
	}
	free (full_response);
	return result;
}
#endif