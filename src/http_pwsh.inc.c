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
char *windows_http_post(const char *url, const char *headers[], const char *data, int *code, int *rlen, int timeout) {
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "$body='%s';", data);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Post -Uri '%s' -Headers $headers -Body $body -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			*code = atoi (full_response);
			char *body = newline + 1;
			if (rlen) {
				*rlen = strlen (body);
			}
			char *result = strdup (body);
			free (full_response);
			return result;
		}
		*code = 200;
		if (rlen) {
			*rlen = strlen (full_response);
		}
		return full_response;
	}
	*code = 0;
	return NULL;
}

/**
 * Windows-specific HTTP GET using PowerShell
 */
char *windows_http_get(const char *url, const char *headers[], int *code, int *rlen, int timeout) {
	RStrBuf *cmd = r_strbuf_new ("powershell -Command \"");
	append_headers_to_cmd (cmd, headers);
	r_strbuf_appendf (cmd, "try{$r=Invoke-WebRequest -Method Get -Uri '%s' -Headers $headers -TimeoutSec %d;", url, timeout);
	r_strbuf_appendf (cmd, "Write-Host $r.StatusCode;$r.Content}catch{Write-Host 0;$_.Exception.Message}\"");
	char *cmd_str = r_strbuf_drain (cmd);
	char *full_response = r_sys_cmd_str (cmd_str, NULL, NULL);
	free (cmd_str);
	if (full_response) {
		char *newline = strchr (full_response, '\n');
		if (newline) {
			*newline = '\0';
			*code = atoi (full_response);
			char *body = newline + 1;
			if (rlen) {
				*rlen = strlen (body);
			}
			char *result = strdup (body);
			free (full_response);
			return result;
		}
		*code = 200;
		if (rlen) {
			*rlen = strlen (full_response);
		}
		return full_response;
	}
	*code = 0;
	return NULL;
}
#endif