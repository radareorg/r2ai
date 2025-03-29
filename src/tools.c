#include "r2ai.h"

// Define the radare2 command tool
static R2AI_Tool r2cmd_tool = {
	.name = "r2cmd",
	.description = "Run a radare2 command",
	.parameters = "{\
		\"type\": \"object\",\
		\"properties\": {\
			\"command\": {\
				\"type\": \"string\",\
				\"description\": \"The radare2 command to run\"\
			}\
		},\
		\"required\": [\"command\"]\
	}"
};

// Create a global tools structure with our tools
static R2AI_Tools r2ai_tools_instance = {
	.tools = &r2cmd_tool,
	.n_tools = 1
};

// Function to get the global tools instance
R_API const R2AI_Tools *r2ai_get_tools(void) {
	return &r2ai_tools_instance;
}

// Function to parse input tools_json (OpenAI format) into R2AI_Tool array
R_API R2AI_Tools *r2ai_tools_parse(const char *tools_json) {
	if (!tools_json) {
		return NULL;
	}
	
	RJson *json = r_json_parse((char *)tools_json);
	if (!json || json->type != R_JSON_ARRAY) {
		R_LOG_ERROR("Invalid tools JSON format - expected array");
		r_json_free(json);
		return NULL;
	}
	
	R2AI_Tools *tools = R_NEW0(R2AI_Tools);
	if (!tools) {
		r_json_free(json);
		return NULL;
	}
	
	int n_tools = json->children.count;
	tools->tools = R_NEWS0(R2AI_Tool, n_tools);
	if (!tools->tools) {
		free(tools);
		r_json_free(json);
		return NULL;
	}
	tools->n_tools = n_tools;
	
	int valid_tools = 0;
	for (int i = 0; i < n_tools; i++) {
		const RJson *tool_json = r_json_item(json, i);
		if (!tool_json || tool_json->type != R_JSON_OBJECT) {
			continue;
		}
		
		const RJson *type = r_json_get(tool_json, "type");
		if (!type || type->type != R_JSON_STRING || strcmp(type->str_value, "function") != 0) {
			continue;
		}
		
		const RJson *function = r_json_get(tool_json, "function");
		if (!function || function->type != R_JSON_OBJECT) {
			continue;
		}
		
		const RJson *name = r_json_get(function, "name");
		const RJson *description = r_json_get(function, "description");
		const RJson *parameters = r_json_get(function, "parameters");
		
		if (!name || name->type != R_JSON_STRING) {
			continue;
		}
		
		R2AI_Tool *tool = &tools->tools[valid_tools++];
		tool->name = strdup(name->str_value);
		
		if (description && description->type == R_JSON_STRING) {
			tool->description = strdup(description->str_value);
		}
		
		if (parameters) {
			// Just pass through the JSON as a string
			if (parameters->type == R_JSON_STRING) {
				tool->parameters = strdup(parameters->str_value);
			} else {
				// Use pj_raw to pass through any other raw JSON
				PJ *pj = pj_new();
				if (pj) {
					pj_raw(pj, "{}");
					char *params_str = pj_drain(pj);
					if (params_str) {
						tool->parameters = strdup(params_str);
						free(params_str);
					}
				}
			}
		}
	}
	
	// Update count of valid tools
	tools->n_tools = valid_tools;
	
	r_json_free(json);
	return tools;
}

// Function to convert R2AI_Tools to OpenAI format JSON
R_API char *r2ai_tools_to_openai_json(const R2AI_Tools *tools) {
	if (!tools || tools->n_tools <= 0) {
		return NULL;
	}
	
	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}
	
	pj_a(pj); // Start array
	
	for (int i = 0; i < tools->n_tools; i++) {
		const R2AI_Tool *tool = &tools->tools[i];
		if (!tool->name) {
			continue;
		}
		
		pj_o(pj); // Start tool object
		pj_ks(pj, "type", "function");
		
		pj_k(pj, "function");
		pj_o(pj); // Start function object
		
		pj_ks(pj, "name", tool->name);
		
		if (tool->description) {
			pj_ks(pj, "description", tool->description);
		}
		
		if (tool->parameters) {
			pj_k(pj, "parameters");
			pj_raw(pj, tool->parameters);
		}
		
		pj_end(pj); // End function object
		pj_end(pj); // End tool object
	}
	
	pj_end(pj); // End array
	
	char *result = pj_drain(pj);
	return result;
}

// Function to convert R2AI_Tools to Anthropic format JSON
R_API char *r2ai_tools_to_anthropic_json(const R2AI_Tools *tools) {
	if (!tools || tools->n_tools <= 0) {
		return NULL;
	}
	
	PJ *pj = pj_new();
	if (!pj) {
		return NULL;
	}
	
	pj_a(pj); // Start array
	
	for (int i = 0; i < tools->n_tools; i++) {
		const R2AI_Tool *tool = &tools->tools[i];
		if (!tool->name) {
			continue;
		}
		
		pj_o(pj); // Start tool object
		
		pj_ks(pj, "name", tool->name);
		
		if (tool->description) {
			pj_ks(pj, "description", tool->description);
		}
		
		if (tool->parameters) {
			pj_k(pj, "input_schema");
			pj_raw(pj, tool->parameters);
		}
		
		pj_end(pj); // End tool object
	}
	
	pj_end(pj); // End array
	
	char *result = pj_drain(pj);
	return result;
}

// Function to free a tools structure
R_API void r2ai_tools_free(R2AI_Tools *tools) {
	if (!tools) {
		return;
	}
	
	if (tools->tools) {
		for (int i = 0; i < tools->n_tools; i++) {
			R2AI_Tool *tool = &tools->tools[i];
			R_FREE(tool->name);
			R_FREE(tool->description);
			R_FREE(tool->parameters);
		}
		R_FREE(tools->tools);
	}
	
	R_FREE(tools);
} 