#include "r2ai.h"

#if R2_VERSION_NUMBER >= 50909

static const char *modelname(const char *model_name) {
	return model_name? model_name: "claude-3-7-sonnet-20250219";
}

// Parse Anthropic-specific tool_use responses
static R2AI_ToolCall *r2ai_anthropic_parse_tool_call(const char *tool_use_json) {
	if (!tool_use_json) {
		return NULL;
	}

	R2AI_ToolCall *tool_call = R_NEW0(R2AI_ToolCall);
	if (!tool_call) {
		return NULL;
	}

	char *json_copy = strdup(tool_use_json);
	if (!json_copy) {
		free(tool_call);
		return NULL;
	}

	RJson *json = r_json_parse(json_copy);
	if (!json || json->type != R_JSON_OBJECT) {
		R_LOG_ERROR("Failed to parse Anthropic tool_use JSON");
		r_json_free(json);
		free(json_copy);
		free(tool_call);
		return NULL;
	}

	// Get the tool name
	const RJson *name = r_json_get(json, "name");
	if (name && name->type == R_JSON_STRING) {
		tool_call->name = strdup(name->str_value);
	} else {
		R_LOG_ERROR("No valid tool name in Anthropic tool_use");
		r_json_free(json);
		free(json_copy);
		free(tool_call);
		return NULL;
	}

	// Get the tool_use ID
	const RJson *id = r_json_get(json, "id");
	if (id && id->type == R_JSON_STRING) {
		tool_call->id = strdup(id->str_value);
	}

	// Parse the arguments from the 'input' object
	const RJson *input = r_json_get(json, "input");
	if (input && input->type == R_JSON_OBJECT) {
		// Convert the entire input object to JSON string for the arguments
		PJ *pj = pj_new();
		if (pj) {
			pj_o(pj);
			
			// Manually iterate through properties in the input object
			const RJson *prop = input->children.first;
			while (prop) {
				if (prop->key) {
					switch (prop->type) {
					case R_JSON_STRING:
						pj_ks(pj, prop->key, prop->str_value);
						break;
					case R_JSON_INTEGER:
						pj_kn(pj, prop->key, prop->num.u_value);
						break;
					case R_JSON_BOOLEAN:
						pj_kb(pj, prop->key, prop->num.u_value ? true : false);
						break;
					case R_JSON_NULL:
						pj_knull(pj, prop->key);
						break;
					case R_JSON_DOUBLE:
						{
							char buf[64];
							snprintf(buf, sizeof(buf), "%f", prop->num.dbl_value);
							pj_ks(pj, prop->key, buf);
						}
						break;
					case R_JSON_OBJECT:
					case R_JSON_ARRAY:
						// For complex types, we'll just use a simplified approach
						// A more complete solution would recursively serialize these
						pj_ks(pj, prop->key, "[complex value]");
						break;
					default:
						// Skip unknown types
						break;
					}
				}
				prop = prop->next;
			}
			
			pj_end(pj);
			tool_call->arguments = pj_drain(pj);
		}
	}

	r_json_free(json);
	free(json_copy);
	return tool_call;
}

R_IPI R2AI_Message *r2ai_anthropic(RCore *core, R2AIArgs args) {
	const char *content = args.input;
	const char *model = args.model;
	char **error = args.error;
	const R2AI_Tools *tools = args.tools;
	R2AI_Messages *messages_input = args.messages;

	if (error) {
		*error = NULL;
	}

	char *apikey = NULL;
	const char *api_key = r_config_get(core->config, "r2ai.anthropic.api_key");
	if (api_key) {
		apikey = strdup(api_key);
	} else {
		char *apikey_file = r_file_new("~/.r2ai.anthropic-key", NULL);
		apikey = r_file_slurp(apikey_file, NULL);
		free(apikey_file);
		if (!apikey) {
			if (error) {
				*error = strdup("Failed to read Anthropic API key from r2ai.anthropic.api_key or ~/.r2ai.anthropic-key");
			}
			return NULL;
		}
	}

	r_str_trim(apikey);

	// Setup HTTP headers
	char *auth_header = r_str_newf("x-api-key: %s", apikey);
	char *anthropic_version = "anthropic-version: 2023-06-01";
	const char *headers[] = {
		"Content-Type: application/json",
		auth_header,
		anthropic_version,
		NULL
	};

	const char *anthropic_url = "https://api.anthropic.com/v1/messages";

	// Extract system message if available
	const char *system_message = NULL;
	if (messages_input && messages_input->n_messages > 0) {
		for (int i = 0; i < messages_input->n_messages; i++) {
			if (!strcmp(messages_input->messages[i].role, "system")) {
				system_message = messages_input->messages[i].content;
				break;
			}
		}
	}

	// If no system message in messages, check config
	if (!system_message) {
		system_message = r_config_get(core->config, "r2ai.system");
	}

	// Create messages JSON
	char *messages_json = NULL;
	
	if (messages_input && messages_input->n_messages > 0) {
		// Filter out system messages for Anthropic API
		R2AI_Messages *filtered_msgs = r2ai_msgs_new();
		if (!filtered_msgs) {
			if (error) {
				*error = strdup("Failed to create messages array");
			}
			free(auth_header);
			free(apikey);
			return NULL;
		}
		
		// Copy all non-system messages
		for (int i = 0; i < messages_input->n_messages; i++) {
			if (strcmp(messages_input->messages[i].role, "system") != 0) {
				r2ai_msgs_add(filtered_msgs, &messages_input->messages[i]);
			}
		}
		
		// Convert to JSON
		messages_json = r2ai_msgs_to_anthropic_json(filtered_msgs);
		r2ai_msgs_free(filtered_msgs);
		
		if (!messages_json) {
			if (error) {
				*error = strdup("Failed to convert messages to JSON");
			}
			free(auth_header);
			free(apikey);
			return NULL;
		}

	} else {
		if (error) {
			*error = strdup("No input or messages provided");
		}
		free(auth_header);
		free(apikey);
		return NULL;
	}

	// Convert tools to Anthropic format if available
	char *anthropic_tools_json = NULL;
	if (tools && tools->n_tools > 0) {
		anthropic_tools_json = r2ai_tools_to_anthropic_json(tools);
	}

	// Create the request JSON
	PJ *pj = pj_new();
	pj_o(pj);
	pj_ks(pj, "model", modelname(model));
	pj_kn(pj, "max_tokens", 4096);
	
	// Add system message if available
	if (system_message) {
		pj_ks(pj, "system", system_message);
	}
	
	// Add messages
	pj_k(pj, "messages");
	// messages_json already contains the array itself, so we use raw
	pj_raw(pj, messages_json);
	
	// Add tools if available
	if (anthropic_tools_json) {
		pj_k(pj, "tools");
		pj_raw(pj, anthropic_tools_json);
		free(anthropic_tools_json);
	}
	
	pj_end(pj);

	char *data = pj_drain(pj);
	free(messages_json);

	// Save the full JSON for debugging
	r_file_dump("/tmp/r2ai_anthropic_request.json", (const ut8*)data, strlen(data), 0);
	R_LOG_INFO("Full request saved to /tmp/r2ai_anthropic_request.json");
	R_LOG_INFO("Anthropic API request data: %s", data);
	
	// Make the API call
	int code = 0;
	char *res = r_socket_http_post(anthropic_url, headers, data, &code, NULL);
	free(data);
	free(auth_header);
	
	if (!res || code != 200) {
		R_LOG_ERROR("Anthropic API error %d", code);
		if (error && res) {
			*error = strdup(res);
		} else if (error) {
			*error = strdup("Failed to get response from Anthropic API");
		}
		free(res);
		free(apikey);
		return NULL;
	}
	
	// Save the response for inspection
	r_file_dump("/tmp/r2ai_anthropic_response.json", (const ut8*)res, strlen(res), 0);
	R_LOG_INFO("Anthropic API response saved to /tmp/r2ai_anthropic_response.json");
	R_LOG_INFO("Anthropic API response: %s", res);
	
	// Parse the response
	R2AI_Message *result = NULL;
	char *response_copy = strdup(res);
	if (response_copy) {
		RJson *jres = r_json_parse(response_copy);
		if (jres) {
			// Create a new message structure
			result = R_NEW0(R2AI_Message);
			if (result) {
				result->role = strdup("assistant");

				RStrBuf *content_buf = r_strbuf_new("");
				
				// Check for tool calls in Anthropic response
				int has_tool_use = 0;
				int n_tool_calls = 0;
				
				// Count tool_use blocks to determine array size
				const RJson *content_array = r_json_get(jres, "content");
				if (content_array && content_array->type == R_JSON_ARRAY) {
					// First count the number of tool_use blocks
					const RJson *content_item = content_array->children.first;
					while (content_item) {
						const RJson *type = r_json_get(content_item, "type");
						if (type && type->type == R_JSON_STRING && !strcmp(type->str_value, "tool_use")) {
							has_tool_use = 1;
							n_tool_calls++;
						}
						content_item = content_item->next;
					}
				}
				
				// Allocate tool_calls array if needed
				if (has_tool_use && n_tool_calls > 0) {
					result->tool_calls = R_NEWS0(R2AI_ToolCall, n_tool_calls);
					if (!result->tool_calls) {
						if (error) {
							*error = strdup("Failed to allocate memory for tool calls");
						}
						r_json_free(jres);
						free(response_copy);
						r2ai_message_free(result);
						free(res);
						free(apikey);
						return NULL;
					}
					result->n_tool_calls = n_tool_calls;
				}
				
				// Process each content item
				int tool_idx = 0;
				if (content_array && content_array->type == R_JSON_ARRAY) {
					const RJson *content_item = content_array->children.first;
					while (content_item) {
						const RJson *type = r_json_get(content_item, "type");
						if (type && type->type == R_JSON_STRING) {
							if (!strcmp(type->str_value, "text")) {
								// Text content
								const RJson *text = r_json_get(content_item, "text");
								if (text && text->type == R_JSON_STRING) {
									r_strbuf_append(content_buf, text->str_value);
								}
							} else if (!strcmp(type->str_value, "tool_use") && tool_idx < n_tool_calls) {
								// Tool call - convert from Anthropic format to OpenAI format
								const RJson *name = r_json_get(content_item, "name");
								const RJson *id = r_json_get(content_item, "id");
								const RJson *input = r_json_get(content_item, "input");
								
								if (name && name->type == R_JSON_STRING) {
									R2AI_ToolCall *tc = (R2AI_ToolCall *)&result->tool_calls[tool_idx];
									tc->name = strdup(name->str_value);
								}
								
								if (id && id->type == R_JSON_STRING) {
									R2AI_ToolCall *tc = (R2AI_ToolCall *)&result->tool_calls[tool_idx];
									tc->id = strdup(id->str_value);
								}
								
								if (input && input->type == R_JSON_OBJECT) {
									// Convert input object to JSON string
									PJ *args_pj = pj_new();
									if (args_pj) {
										pj_o(args_pj);
										
										// Process all properties in the input object
										const RJson *prop = input->children.first;
										while (prop) {
											if (prop->key) {
												switch (prop->type) {
												case R_JSON_STRING:
													pj_ks(args_pj, prop->key, prop->str_value);
													break;
												case R_JSON_INTEGER:
													pj_kn(args_pj, prop->key, prop->num.u_value);
													break;
												case R_JSON_BOOLEAN:
													pj_kb(args_pj, prop->key, prop->num.u_value ? true : false);
													break;
												case R_JSON_NULL:
													pj_knull(args_pj, prop->key);
													break;
												case R_JSON_DOUBLE:
													{
														char buf[64];
														snprintf(buf, sizeof(buf), "%f", prop->num.dbl_value);
														pj_ks(args_pj, prop->key, buf);
													}
													break;
												case R_JSON_OBJECT:
												case R_JSON_ARRAY:
													// For complex types, we'll just use a simplified approach
													pj_ks(args_pj, prop->key, "[complex value]");
													break;
												default:
													// Skip unknown types
													break;
												}
											}
											prop = prop->next;
										}
										
										pj_end(args_pj);
										char *args_str = pj_drain(args_pj);
										if (args_str) {
											R2AI_ToolCall *tc = (R2AI_ToolCall *)&result->tool_calls[tool_idx];
											tc->arguments = args_str;
										}
									}
								}
								
								tool_idx++;
							}
						}
						content_item = content_item->next;
					}
				}
				
				// Store the content
				result->content = r_strbuf_drain(content_buf);
				
				// If there's no content and no tool calls, clean up
				if (!result->content && !result->n_tool_calls) {
					r2ai_message_free(result);
					result = NULL;
				}
			}
			r_json_free(jres);
		}
		free(response_copy);
	}
	
	free(res);
	free(apikey);
	return result;
}

R_IPI char *r2ai_anthropic_stream(RCore *core, R2AIArgs args) {
	// Not implemented yet
	return NULL;
}

#endif
