}
args.provider = strdup(provider);

const char *api_key_env = r_str_newf("%s_API_KEY", provider);
r_str_case(api_key_env, true);
const char *api_key_config = r_str_newf("r2ai.%s.api_key", provider);
const char *api_key_filename = r_str_newf("~/.r2ai.%s-key", provider);
if (r_config_get(core->config, api_key_config)) {
	args.api_key = strdup (r_config_get (core->config, api_key_config));
} else if (r_file_exists(api_key_filename)) {
	char *apikey_file = r_file_new (api_key_filename, NULL);
	args.api_key = r_file_slurp (apikey_file, NULL);
	free (apikey_file);
} else if (getenv(api_key_env)) {
	args.api_key = strdup (getenv (api_key_env));
}
r_str_trim(args.api_key);
R_LOG_INFO("Using provider: %s", provider);
if (strcmp(provider, "anthropic") == 0) {
	res = r2ai_anthropic (core, args);
} else {
