/* r2ai - Copyright 2023-2025 dnakov, pancake */

#include "r2ai.h"

// Static global message store for session persistence
static R2AI_Messages *conversation = NULL;

#define INITIAL_CAPACITY 8
#define GROWTH_FACTOR    1.5

R_API void r2ai_message_free(R2AI_Message *msg) {
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

	if (msg->content_blocks) {
		for (int i = 0; i < msg->content_blocks->n_blocks; i++) {
			R2AI_ContentBlock *block = &msg->content_blocks->blocks[i];
			free ((void *)block->type);
			free ((void *)block->data);
			free ((void *)block->thinking);
			free ((void *)block->signature);
			free ((void *)block->text);
			free ((void *)block->id);
			free ((void *)block->name);
			free ((void *)block->input);
		}
		free ((void *)msg->content_blocks->blocks);
		free ((void *)msg->content_blocks);
	}

	// Clear the struct but don't free it
	memset (msg, 0, sizeof (R2AI_Message));
}

// Initialize conversation container (call this during plugin init)
R_API void r2ai_conversation_init(void) {
	if (conversation) {
		// Already initialized
		return;
	}

	conversation = R_NEW0 (R2AI_Messages);
	if (!conversation) {
		return;
	}
	conversation->cap_messages = INITIAL_CAPACITY;
	conversation->messages = R_NEWS0 (R2AI_Message, conversation->cap_messages);
	if (!conversation->messages) {
		R_FREE (conversation);
	}
}

// Get the conversation instance (returns NULL if not initialized)
R_API R2AI_Messages *r2ai_conversation_get(void) {
	return conversation;
}

// Create a new temporary messages container
R_API R2AI_Messages *r2ai_msgs_new(void) {
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

R_API void r2ai_msgs_free(R2AI_Messages *msgs) {
	if (!msgs) {
		return;
	}

	// Don't actually free if it's our static instance
	if (msgs == conversation) {
		// Just clear the messages but keep the allocated structure
		for (int i = 0; i < msgs->n_messages; i++) {
			r2ai_message_free (&msgs->messages[i]);
		}
		msgs->n_messages = 0;
		return;
	}

	// Normal free for non-static instances
	if (msgs->messages) {
		for (int i = 0; i < msgs->n_messages; i++) {
			r2ai_message_free (&msgs->messages[i]);
		}
		R_FREE (msgs->messages);
	}

	R_FREE (msgs);
}

// Free the conversation when plugin is unloaded
R_API void r2ai_conversation_free(void) {
	if (conversation) {
		if (conversation->messages) {
			for (int i = 0; i < conversation->n_messages; i++) {
				r2ai_message_free (&conversation->messages[i]);
			}
			R_FREE (conversation->messages);
		}
		R_FREE (conversation);
		conversation = NULL;
	}
}

// Clear messages in a container without freeing the container itself
R_API void r2ai_msgs_clear(R2AI_Messages *msgs) {
	if (!msgs) {
		return;
	}

	for (int i = 0; i < msgs->n_messages; i++) {
		r2ai_message_free (&msgs->messages[i]);
	}
	msgs->n_messages = 0;
}

R_API bool r2ai_msgs_add(R2AI_Messages *msgs, const R2AI_Message *msg) {
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

	if (msg->content_blocks) {
		R2AI_ContentBlocks *cb = R_NEW0 (R2AI_ContentBlocks);
		if (!cb) {
			r2ai_message_free (dest);
			msgs->n_messages--;
			return false;
		}
		cb->n_blocks = msg->content_blocks->n_blocks;
		cb->blocks = R_NEWS0 (R2AI_ContentBlock, cb->n_blocks);
		if (!cb->blocks) {
			free (cb);
			r2ai_message_free (dest);
			msgs->n_messages--;
			return false;
		}
		for (int i = 0; i < cb->n_blocks; i++) {
			R2AI_ContentBlock *src = &msg->content_blocks->blocks[i];
			R2AI_ContentBlock *dst = &cb->blocks[i];
			dst->type = src->type ? strdup (src->type) : NULL;
			dst->data = src->data ? strdup (src->data) : NULL;
			dst->thinking = src->thinking ? strdup (src->thinking) : NULL;
			dst->signature = src->signature ? strdup (src->signature) : NULL;
			dst->text = src->text ? strdup (src->text) : NULL;
			dst->id = src->id ? strdup (src->id) : NULL;
			dst->name = src->name ? strdup (src->name) : NULL;
			dst->input = src->input ? strdup (src->input) : NULL;
		}
		dest->content_blocks = cb;
	}

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

R_API bool r2ai_msgs_add_tool_call(R2AI_Messages *msgs, const R2AI_ToolCall *tc) {
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

R_API bool r2ai_msgs_from_response(R2AI_Messages *msgs, const char *json_str) {
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

R_API bool r2ai_msgs_from_json(R2AI_Messages *msgs, const RJson *json) {
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
	const RJson *content_blocks = r_json_get (message, "content_blocks");

	// Create a new message to add
	R2AI_Message new_msg = { 0 };
	new_msg.role = (role && role->type == R_JSON_STRING) ? strdup (role->str_value) : strdup ("assistant");
	new_msg.content = (content && content->type == R_JSON_STRING) ? strdup (content->str_value) : NULL;
	new_msg.tool_call_id = NULL;
	new_msg.tool_calls = NULL;
	new_msg.n_tool_calls = 0;

	if (content_blocks && content_blocks->type == R_JSON_ARRAY && content_blocks->children.count > 0) {
		R2AI_ContentBlocks *cb = R_NEW0 (R2AI_ContentBlocks);
		if (!cb) {
			r2ai_message_free (&new_msg);
			return false;
		}
		cb->n_blocks = content_blocks->children.count;
		cb->blocks = R_NEWS0 (R2AI_ContentBlock, cb->n_blocks);
		if (!cb->blocks) {
			free (cb);
			r2ai_message_free (&new_msg);
			return false;
		}
		for (int i = 0; i < cb->n_blocks; i++) {
			const RJson *block = r_json_item (content_blocks, i);
			if (!block) {
				continue;
			}
			R2AI_ContentBlock *dst = &cb->blocks[i];
			const RJson *type = r_json_get (block, "type");
			const RJson *data = r_json_get (block, "data");
			const RJson *thinking = r_json_get (block, "thinking");
			const RJson *signature = r_json_get (block, "signature");
			const RJson *text = r_json_get (block, "text");
			const RJson *id = r_json_get (block, "id");
			const RJson *name = r_json_get (block, "name");
			const RJson *input = r_json_get (block, "input");

			dst->type = (type && type->type == R_JSON_STRING) ? strdup (type->str_value) : NULL;
			dst->data = (data && data->type == R_JSON_STRING) ? strdup (data->str_value) : NULL;
			dst->thinking = (thinking && thinking->type == R_JSON_STRING) ? strdup (thinking->str_value) : NULL;
			dst->signature = (signature && signature->type == R_JSON_STRING) ? strdup (signature->str_value) : NULL;
			dst->text = (text && text->type == R_JSON_STRING) ? strdup (text->str_value) : NULL;
			dst->id = (id && id->type == R_JSON_STRING) ? strdup (id->str_value) : NULL;
			dst->name = (name && name->type == R_JSON_STRING) ? strdup (name->str_value) : NULL;
			dst->input = (input && input->type == R_JSON_STRING) ? strdup (input->str_value) : NULL;
		}
		new_msg.content_blocks = cb;
	}

	// Add the message without tool calls first
	if (!r2ai_msgs_add (msgs, &new_msg)) {
		r2ai_message_free (&new_msg);
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

R_API char *r2ai_msgs_to_json(const R2AI_Messages *msgs) {
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

R_API char *r2ai_msgs_to_anthropic_json(const R2AI_Messages *msgs) {
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

		if (msg->content_blocks) {
			pj_ka (pj, "content"); // Start content array
			for (int j = 0; j < msg->content_blocks->n_blocks; j++) {
				const R2AI_ContentBlock *block = &msg->content_blocks->blocks[j];
				pj_o (pj); // Start content block object
				if (R_STR_ISNOTEMPTY (block->type)) {
					pj_ks (pj, "type", block->type);
				}
				if (R_STR_ISNOTEMPTY (block->data)) {
					pj_ks (pj, "data", block->data);
				}
				if (R_STR_ISNOTEMPTY (block->thinking)) {
					pj_ks (pj, "thinking", block->thinking);
				}
				if (R_STR_ISNOTEMPTY (block->signature)) {
					pj_ks (pj, "signature", block->signature);
				}
				if (R_STR_ISNOTEMPTY (block->text)) {
					pj_ks (pj, "text", block->text);
				}
				if (R_STR_ISNOTEMPTY (block->id)) {
					pj_ks (pj, "id", block->id);
				}
				if (R_STR_ISNOTEMPTY (block->name)) {
					pj_ks (pj, "name", block->name);
				}
				if (R_STR_ISNOTEMPTY (block->input)) {
					// Try to parse the input as JSON first
					char *input_str = strdup (block->input);
					RJson *input_json = r_json_parse (input_str);
					if (input_json) {
						// If it's valid JSON, add it directly
						pj_ko (pj, "input");
						r_json_to_pj (input_json, pj);
						pj_end (pj);
						r_json_free (input_json);
					} else {
						// If not valid JSON, create a basic object with command
						pj_ko (pj, "input");
						pj_ks (pj, "command", block->input);
						pj_end (pj);
					}
					free (input_str);
				}
				pj_end (pj); // End content block object
			}
			pj_end (pj); // End content array
		} else {
			pj_ka (pj, "content"); // Start content array

			if (msg->content) {
				pj_o (pj); // Start content block object
				if (strcmp (msg->role, "tool") == 0) {
					pj_ks (pj, "type", "tool_result");
					pj_ks (pj, "tool_use_id", msg->tool_call_id);
					pj_ks (pj, "content", msg->content);
				} else {
					pj_ks (pj, "type", "text");
					pj_ks (pj, "text", msg->content);
				}
				pj_end (pj); // End content block object
			}

			if (msg->tool_calls && msg->n_tool_calls > 0) {
				pj_k (pj, "tool_calls");
				pj_a (pj); // Start tool_calls array

				for (int j = 0; j < msg->n_tool_calls; j++) {
					const R2AI_ToolCall *tc = &msg->tool_calls[j];
					pj_o (pj); // Start tool_calls object
					pj_ks (pj, "type", "tool_use");
					pj_ks (pj, "id", tc->id ? tc->id : "");
					pj_ks (pj, "name", tc->name ? tc->name : "");

					// Create a non-const copy for r_json_parse
					char *arguments_copy = tc->arguments ? strdup (tc->arguments) : NULL;
					RJson *arguments = arguments_copy ? r_json_parse (arguments_copy) : NULL;

					pj_ko (pj, "input"); // Start input object
					if (arguments) {
						for (int k = 0; k < arguments->children.count; k++) {
							const RJson *arg = r_json_item (arguments, k);
							if (arg && arg->type == R_JSON_STRING) {
								pj_ks (pj, arg->key, arg->str_value);
							}
						}
						r_json_free (arguments);
					}
					free (arguments_copy);

					pj_end (pj); // End input object
					pj_end (pj); // End tool_calls object
				}

				pj_end (pj); // End tool_calls array
			}
			pj_end (pj); // End content array
		}
		pj_end (pj); // End message object
	}

	pj_end (pj); // End array

	char *result = pj_drain (pj);
	return result;
}

// Function to delete the last N messages from conversation history
R_API void r2ai_delete_last_messages(R2AI_Messages *messages, int n) {
	if (!messages || messages->n_messages == 0) {
		return;
	}

	// If n is not specified or invalid, default to deleting the last message
	if (n <= 0) {
		n = 1;
	}

	// Make sure we don't try to delete more messages than exist
	if (n > messages->n_messages) {
		n = messages->n_messages;
	}

	// Free the last n messages
	for (int i = messages->n_messages - n; i < messages->n_messages; i++) {
		r2ai_message_free (&messages->messages[i]);
	}

	// Update the message count
	messages->n_messages -= n;
}

// Helper function to convert RJson to PJ without draining
R_API PJ *r_json_to_pj(const RJson *json, PJ *existing_pj) {
	if (!json) {
		return existing_pj;
	}

	PJ *pj = existing_pj ? existing_pj : pj_new ();
	if (!pj) {
		return NULL;
	}

	switch (json->type) {
	case R_JSON_STRING:
		pj_s (pj, json->str_value);
		break;
	case R_JSON_INTEGER:
		pj_n (pj, json->num.u_value);
		break;
	case R_JSON_DOUBLE:
		pj_d (pj, json->num.dbl_value);
		break;
	case R_JSON_BOOLEAN:
		pj_b (pj, json->num.u_value);
		break;
	case R_JSON_NULL:
		pj_null (pj);
		break;
	case R_JSON_OBJECT:
		if (!existing_pj) {
			pj_o (pj);
		}

		// Handle object's properties
		const RJson *prop = json->children.first;
		while (prop) {
			if (prop->key) {
				switch (prop->type) {
				case R_JSON_STRING:
					pj_ks (pj, prop->key, prop->str_value);
					break;
				case R_JSON_INTEGER:
					pj_kn (pj, prop->key, prop->num.u_value);
					break;
				case R_JSON_DOUBLE:
					pj_kd (pj, prop->key, prop->num.dbl_value);
					break;
				case R_JSON_BOOLEAN:
					pj_kb (pj, prop->key, prop->num.u_value);
					break;
				case R_JSON_NULL:
					pj_knull (pj, prop->key);
					break;
				case R_JSON_OBJECT:
					pj_ko (pj, prop->key);
					if (!r_json_to_pj (prop, pj)) {
						if (!existing_pj) {
							pj_free (pj);
						}
						return NULL;
					}
					pj_end (pj);
					break;
				case R_JSON_ARRAY:
					pj_ka (pj, prop->key);
					if (!r_json_to_pj (prop, pj)) {
						if (!existing_pj) {
							pj_free (pj);
						}
						return NULL;
					}
					pj_end (pj);
					break;
				default:
					break;
				}
			}
			prop = prop->next;
		}

		if (!existing_pj) {
			pj_end (pj);
		}
		break;

	case R_JSON_ARRAY:
		if (!existing_pj) {
			pj_a (pj);
		}

		// Handle array items
		const RJson *item = json->children.first;
		while (item) {
			switch (item->type) {
			case R_JSON_STRING:
				pj_s (pj, item->str_value);
				break;
			case R_JSON_INTEGER:
				pj_n (pj, item->num.u_value);
				break;
			case R_JSON_DOUBLE:
				pj_d (pj, item->num.dbl_value);
				break;
			case R_JSON_BOOLEAN:
				pj_b (pj, item->num.u_value);
				break;
			case R_JSON_NULL:
				pj_null (pj);
				break;
			case R_JSON_OBJECT:
				pj_o (pj);
				if (!r_json_to_pj (item, pj)) {
					if (!existing_pj) {
						pj_free (pj);
					}
					return NULL;
				}
				pj_end (pj);
				break;
			case R_JSON_ARRAY:
				pj_a (pj);
				if (!r_json_to_pj (item, pj)) {
					if (!existing_pj) {
						pj_free (pj);
					}
					return NULL;
				}
				pj_end (pj);
				break;
			default:
				break;
			}
			item = item->next;
		}

		if (!existing_pj) {
			pj_end (pj);
		}
		break;

	default:
		if (!existing_pj) {
			pj_free (pj);
		}
		return NULL;
	}

	return pj;
}

// Helper function to clone RJson to string
R_API char *r_json_to_string(const RJson *json) {
	PJ *pj = r_json_to_pj (json, NULL);
	if (!pj) {
		return NULL;
	}
	char *result = pj_drain (pj);
	return result;
}

// Create a conversation with optional initial user message
R_API R2AI_Messages *create_conversation(const char *user_message) {
	// Create a temporary message container (not using static storage)
	R2AI_Messages *msgs = r2ai_msgs_new ();
	if (!msgs) {
		return NULL;
	}

	// Add user message if provided (no system message - that's added during processing)
	if (R_STR_ISNOTEMPTY (user_message)) {
		R2AI_Message user_msg = {
			.role = "user",
			.content = user_message
		};
		r2ai_msgs_add (msgs, &user_msg);
	}

	return msgs;
}
