/* r2ai - Copyright 2023-2025 pancake */

#include "r2ai.h"

#define INITIAL_CAPACITY 8
#define GROWTH_FACTOR    1.5

static void r2ai_tool_call_free (R2AI_ToolCall *tc) {
	if (!tc) {
		return;
	}
	R_FREE (tc->name);
	R_FREE (tc->arguments);
	R_FREE (tc->id);
}

R_API void r2ai_message_free (R2AI_Message *msg) {
	if (!msg) {
		return;
	}

	free ((void *)msg->role);
	free ((void *)msg->content);
	free ((void *)msg->tool_call_id);

	// Free tool calls
	if (msg->tool_calls) {
		for (int i = 0; i < msg->n_tool_calls; i++) {
			free ((void *)msg->tool_calls[i].id);
			free ((void *)msg->tool_calls[i].name);
			free ((void *)msg->tool_calls[i].arguments);
		}
		free ((void *)msg->tool_calls);
	}

	// Clear the struct but don't free it
	memset (msg, 0, sizeof (R2AI_Message));
}

R_API R2AI_Messages *r2ai_msgs_new (void) {
	R2AI_Messages *msgs = R_NEW0 (R2AI_Messages);
	if (!msgs) {
		return NULL;
	}
	msgs->cap_messages = INITIAL_CAPACITY;
	msgs->messages = R_NEWS0 (R2AI_Message, msgs->cap_messages);
	if (!msgs->messages) {
		R_FREE (msgs);
		return NULL;
	}
	return msgs;
}

R_API void r2ai_msgs_free (R2AI_Messages *msgs) {
	if (!msgs) {
		return;
	}

	if (msgs->messages) {
		for (int i = 0; i < msgs->n_messages; i++) {
			r2ai_message_free (&msgs->messages[i]);
		}
		R_FREE (msgs->messages);
	}

	R_FREE (msgs);
}

R_API bool r2ai_msgs_add (R2AI_Messages *msgs, const R2AI_Message *msg) {
	if (!msgs || !msg) {
		return false;
	}

	// Check if we need to resize
	if (msgs->n_messages >= msgs->cap_messages) {
		int new_cap = msgs->cap_messages * GROWTH_FACTOR;
		R2AI_Message *new_messages = realloc (msgs->messages, sizeof (R2AI_Message) * new_cap);
		if (!new_messages) {
			return false;
		}
		msgs->messages = new_messages;
		msgs->cap_messages = new_cap;

		// Zero the newly allocated portion
		memset (&msgs->messages[msgs->n_messages], 0,
			sizeof (R2AI_Message) * (msgs->cap_messages - msgs->n_messages));
	}

	// Copy the message to the array
	R2AI_Message *dest = &msgs->messages[msgs->n_messages++];
	dest->role = msg->role ? strdup (msg->role) : NULL;
	dest->content = msg->content ? strdup (msg->content) : NULL;
	dest->tool_call_id = msg->tool_call_id ? strdup (msg->tool_call_id) : NULL;
	dest->tool_calls = NULL;
	dest->n_tool_calls = 0;

	// Copy tool calls if any
	if (msg->tool_calls && msg->n_tool_calls > 0) {
		dest->tool_calls = R_NEWS0 (R2AI_ToolCall, msg->n_tool_calls);
		if (!dest->tool_calls) {
			// Clean up and return error
			r2ai_message_free (dest);
			msgs->n_messages--;
			return false;
		}

		dest->n_tool_calls = msg->n_tool_calls;
		for (int i = 0; i < msg->n_tool_calls; i++) {
			const R2AI_ToolCall *src_tc = &msg->tool_calls[i];
			R2AI_ToolCall *dst_tc = (R2AI_ToolCall *)&dest->tool_calls[i];

			dst_tc->name = src_tc->name ? strdup (src_tc->name) : NULL;
			dst_tc->arguments = src_tc->arguments ? strdup (src_tc->arguments) : NULL;
			dst_tc->id = src_tc->id ? strdup (src_tc->id) : NULL;
		}
	}

	return true;
}

R_API bool r2ai_msgs_add_tool_call (R2AI_Messages *msgs, const R2AI_ToolCall *tc) {
	if (!msgs || !tc || msgs->n_messages == 0) {
		return false;
	}

	R2AI_Message *msg = &msgs->messages[msgs->n_messages - 1];

	// Allocate or resize the tool_calls array
	if (msg->n_tool_calls == 0) {
		msg->tool_calls = R_NEWS0 (R2AI_ToolCall, 1);
		if (!msg->tool_calls) {
			return false;
		}
	} else {
		R2AI_ToolCall *new_tool_calls = realloc (
			(void *)msg->tool_calls,
			sizeof (R2AI_ToolCall) * (msg->n_tool_calls + 1));
		if (!new_tool_calls) {
			return false;
		}
		msg->tool_calls = new_tool_calls;
		// Zero the new element
		memset ((void *)&msg->tool_calls[msg->n_tool_calls], 0, sizeof (R2AI_ToolCall));
	}

	// Copy the tool call
	R2AI_ToolCall *dst_tc = (R2AI_ToolCall *)&msg->tool_calls[msg->n_tool_calls];
	dst_tc->name = tc->name ? strdup (tc->name) : NULL;
	dst_tc->arguments = tc->arguments ? strdup (tc->arguments) : NULL;
	dst_tc->id = tc->id ? strdup (tc->id) : NULL;

	msg->n_tool_calls++;
	return true;
}

R_API bool r2ai_msgs_from_response (R2AI_Messages *msgs, const char *json_str) {
	if (!msgs || !json_str) {
		return false;
	}

	// r_json_parse expects non-const char*, so we need to cast it
	RJson *json = r_json_parse ((char *)json_str);
	if (!json) {
		return false;
	}

	bool result = r2ai_msgs_from_json (msgs, json);
	r_json_free (json);
	return result;
}

R_API bool r2ai_msgs_from_json (R2AI_Messages *msgs, const RJson *json) {
	if (!msgs || !json) {
		return false;
	}

	const RJson *choices = r_json_get (json, "choices");
	if (!choices || choices->type != R_JSON_ARRAY) {
		return false;
	}

	const RJson *choice = r_json_item (choices, 0);
	if (!choice) {
		return false;
	}

	const RJson *message = r_json_get (choice, "message");
	if (!message) {
		return false;
	}

	const RJson *role = r_json_get (message, "role");
	const RJson *content = r_json_get (message, "content");

	// Create a new message to add
	R2AI_Message new_msg = { 0 };
	new_msg.role = (role && role->type == R_JSON_STRING) ? strdup (role->str_value) : strdup ("assistant");
	new_msg.content = (content && content->type == R_JSON_STRING) ? strdup (content->str_value) : NULL;
	new_msg.tool_call_id = NULL;
	new_msg.tool_calls = NULL;
	new_msg.n_tool_calls = 0;

	// Add the message without tool calls first
	if (!r2ai_msgs_add (msgs, &new_msg)) {
		return false;
	}

	// Now add tool calls if present
	const RJson *tool_calls = r_json_get (message, "tool_calls");
	if (tool_calls && tool_calls->type == R_JSON_ARRAY) {
		// Iterate through array elements
		for (size_t i = 0; i < tool_calls->children.count; i++) {
			const RJson *tool_call = r_json_item (tool_calls, i);
			if (!tool_call) {
				continue;
			}

			const RJson *id = r_json_get (tool_call, "id");
			const RJson *function = r_json_get (tool_call, "function");
			if (!function) {
				continue;
			}

			const RJson *name = r_json_get (function, "name");
			const RJson *arguments = r_json_get (function, "arguments");

			R2AI_ToolCall tc = { 0 };
			tc.name = (name && name->type == R_JSON_STRING) ? name->str_value : NULL;
			tc.arguments = (arguments && arguments->type == R_JSON_STRING) ? arguments->str_value : NULL;
			tc.id = (id && id->type == R_JSON_STRING) ? id->str_value : NULL;

			if (!r2ai_msgs_add_tool_call (msgs, &tc)) {
				break;
			}
		}
	}

	return true;
}

R_API char *r2ai_msgs_to_json (const R2AI_Messages *msgs) {
	if (!msgs || msgs->n_messages == 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	for (int i = 0; i < msgs->n_messages; i++) {
		const R2AI_Message *msg = &msgs->messages[i];

		pj_o (pj); // Start message object

		// Add role
		pj_ks (pj, "role", msg->role ? msg->role : "user");

		// Add content if present
		if (msg->content) {
			pj_ks (pj, "content", msg->content);
		}

		// Add tool_call_id if present
		if (msg->tool_call_id) {
			pj_ks (pj, "tool_call_id", msg->tool_call_id);
		}

		// Add tool_calls if present
		if (msg->tool_calls && msg->n_tool_calls > 0) {
			pj_k (pj, "tool_calls");
			pj_a (pj); // Start tool_calls array

			for (int j = 0; j < msg->n_tool_calls; j++) {
				const R2AI_ToolCall *tc = &msg->tool_calls[j];

				pj_o (pj); // Start tool call object

				// Add id if present
				if (tc->id) {
					pj_ks (pj, "id", tc->id);
				}

				// Add type (required by OpenAI API)
				pj_ks (pj, "type", "function");

				// Add function object
				pj_k (pj, "function");
				pj_o (pj); // Start function object

				// Add name
				pj_ks (pj, "name", tc->name ? tc->name : "");

				// Add arguments if present
				if (tc->arguments) {
					pj_ks (pj, "arguments", tc->arguments);
				}

				pj_end (pj); // End function object
				pj_end (pj); // End tool call object
			}

			pj_end (pj); // End tool_calls array
		}

		pj_end (pj); // End message object
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

R_API char *r2ai_msgs_to_anthropic_json (const R2AI_Messages *msgs) {
	if (!msgs || msgs->n_messages == 0) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	for (int i = 0; i < msgs->n_messages; i++) {
		const R2AI_Message *msg = &msgs->messages[i];

		pj_o (pj); // Start message object

		// Add role

		const char *role = msg->role ? msg->role : "user";

		pj_ks (pj, "role", strcmp (role, "tool") == 0 ? "user" : role);

		pj_ka (pj, "content"); // Start content array

		if (strcmp (role, "tool") == 0) {
			pj_o (pj); // Start content object
			pj_ks (pj, "type", "tool_result");
			pj_ks (pj, "tool_use_id", msg->tool_call_id);
			pj_ks (pj, "content", msg->content && strcmp (msg->content, "") != 0 ? msg->content : "<no content>");
			pj_end (pj); // End content object
		}
		if (msg->content && strcmp (msg->content, "") != 0) {
			pj_o (pj); // Start content object
			pj_ks (pj, "type", "text");
			pj_ks (pj, "text", msg->content);
			pj_end (pj); // End content object
		}
		for (int j = 0; j < msg->n_tool_calls; j++) {
			const R2AI_ToolCall *tc = &msg->tool_calls[j];
			pj_o (pj); // Start tool_calls object
			pj_ks (pj, "type", "tool_use");
			pj_ks (pj, "id", tc->id ? tc->id : "");
			pj_ks (pj, "name", tc->name ? tc->name : "");
			const RJson *arguments = r_json_parse (tc->arguments);
			pj_ko (pj, "input"); // Start input object
			for (int k = 0; k < arguments->children.count; k++) {
				const RJson *arg = r_json_item (arguments, k);
				if (arg && arg->type == R_JSON_STRING) {
					pj_ks (pj, arg->key, arg->str_value);
				}
			}
			pj_end (pj); // End input object

			r_json_free (arguments);

			pj_end (pj); // End tool_calls object
		}
		pj_end (pj); // End content array
		pj_end (pj); // End message object
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}
