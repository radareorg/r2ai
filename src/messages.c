/* r2ai - Copyright 2023-2025 dnakov, pancake */

#include "r2ai.h"

R_API void r2ai_tool_call_free(R2AI_ToolCall *tc) {
	if (!tc) {
		return;
	}
	free ((void *)tc->id);
	free ((void *)tc->name);
	free ((void *)tc->arguments);
	free (tc);
}

R_API RList *r2ai_content_blocks_new(void) {
	RList *cb = r_list_new ();
	if (!cb) {
		return NULL;
	}
	cb->free = (RListFree)free; // ContentBlocks contain pointers to structs, not structs themselves
	return cb;
}

R_API void r2ai_content_blocks_free(RList *cb) {
	if (!cb) {
		return;
	}
	r_list_free (cb);
}

R_API void r2ai_message_free(R2AI_Message *msg) {
	if (!msg) {
		return;
	}
	free (msg->role);
	free ((void *)msg->content); // maybe double free
	free (msg->reasoning_content);
	free (msg->tool_call_id);

	// Free tool calls
	if (msg->tool_calls) {
		r_list_free (msg->tool_calls);
	}

	if (msg->content_blocks) {
		r2ai_content_blocks_free (msg->content_blocks);
	}
	free (msg);
}

// Conversation is now stored in R2AI_State

R_API void r2ai_conversation_init(R2AI_State *state) {
	if (!state || state->conversation) {
		// Already initialized or invalid state
		return;
	}

	state->conversation = r2ai_msgs_new ();
}

R_API RList *r2ai_conversation_get(R2AI_State *state) {
	return state? state->conversation: NULL;
}

// Create a new temporary messages container
R_API RList *r2ai_msgs_new(void) {
	RList *msgs = r_list_new ();
	if (!msgs) {
		return NULL;
	}
	msgs->free = (RListFree)r2ai_message_free;
	return msgs;
}

R_API void r2ai_msgs_free(RList *msgs) {
	if (msgs) {
		r_list_free (msgs);
	}
}

// Free the conversation when plugin is unloaded
R_API void r2ai_conversation_free(R2AI_State *state) {
	if (state && state->conversation) {
		r2ai_msgs_free (state->conversation);
		state->conversation = NULL;
	}
}

// Clear messages in a container without freeing the container itself
R_API void r2ai_msgs_clear(RList *msgs) {
	if (!msgs) {
		return;
	}
	r_list_purge (msgs);
}

R_API bool r2ai_msgs_add(RList *msgs, const R2AI_Message *msg) {
	if (!msgs || !msg) {
		return false;
	}

	R2AI_Message *new_msg = R_NEW0 (R2AI_Message);
	new_msg->role = msg->role? strdup (msg->role): NULL;
	new_msg->content = msg->content? strdup (msg->content): NULL;
	new_msg->reasoning_content = msg->reasoning_content? strdup (msg->reasoning_content): NULL;

	if (msg->content_blocks) {
		RList *cb = r2ai_content_blocks_new ();
		if (!cb) {
			r2ai_message_free (new_msg);
			free (new_msg);
			return false;
		}
		RListIter *iter;
		R2AI_ContentBlock *src;
		r_list_foreach (msg->content_blocks, iter, src) {
			R2AI_ContentBlock *dst = R_NEW0 (R2AI_ContentBlock);
			dst->type = src->type? strdup (src->type): NULL;
			dst->data = src->data? strdup (src->data): NULL;
			dst->thinking = src->thinking? strdup (src->thinking): NULL;
			dst->signature = src->signature? strdup (src->signature): NULL;
			dst->text = src->text? strdup (src->text): NULL;
			dst->id = src->id? strdup (src->id): NULL;
			dst->name = src->name? strdup (src->name): NULL;
			dst->input = src->input? strdup (src->input): NULL;
			r_list_append (cb, dst);
		}
		new_msg->content_blocks = cb;
	}

	new_msg->tool_call_id = msg->tool_call_id? strdup (msg->tool_call_id): NULL;
	new_msg->tool_calls = r_list_new ();
	if (!new_msg->tool_calls) {
		r2ai_message_free (new_msg);
		free (new_msg);
		return false;
	}
	new_msg->tool_calls->free = (RListFree)r2ai_tool_call_free;

	// Copy tool calls if any
	if (msg->tool_calls) {
		RListIter *iter;
		R2AI_ToolCall *src_tc;
		r_list_foreach (msg->tool_calls, iter, src_tc) {
			R2AI_ToolCall *dst_tc = R_NEW0 (R2AI_ToolCall);
			dst_tc->name = src_tc->name? strdup (src_tc->name): NULL;
			dst_tc->arguments = src_tc->arguments? strdup (src_tc->arguments): NULL;
			dst_tc->id = src_tc->id? strdup (src_tc->id): NULL;
			r_list_append (new_msg->tool_calls, dst_tc);
		}
	}

	r_list_append (msgs, new_msg);
	return true;
}

R_API bool r2ai_msgs_add_tool_call(RList *msgs, const R2AI_ToolCall *tc) {
	if (!msgs || !tc || r_list_empty (msgs)) {
		return false;
	}

	R2AI_Message *msg = r_list_get_n (msgs, r_list_length (msgs) - 1);

	// Ensure tool_calls list exists
	if (!msg->tool_calls) {
		msg->tool_calls = r_list_new ();
		if (!msg->tool_calls) {
			return false;
		}
		msg->tool_calls->free = (RListFree)r2ai_tool_call_free;
	}

	// Copy the tool call
	R2AI_ToolCall *dst_tc = R_NEW0 (R2AI_ToolCall);
	dst_tc->name = tc->name? strdup (tc->name): NULL;
	dst_tc->arguments = tc->arguments? strdup (tc->arguments): NULL;
	dst_tc->id = tc->id? strdup (tc->id): NULL;

	r_list_append (msg->tool_calls, dst_tc);
	return true;
}

R_API bool r2ai_msgs_from_response(RList *msgs, const char *json_str) {
	if (!msgs || !json_str) {
		return false;
	}

	bool result = false;
	// r_json_parse expects (and modifies) non-const char*, so we need to cast it
	RJson *json = r_json_parse ((char *)json_str);
	if (json) {
		result = r2ai_msgs_from_json (msgs, json);
		r_json_free (json);
	}
	return result;
}

R_API bool r2ai_msgs_from_json(RList *msgs, const RJson *json) {
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
	new_msg.role = (role && role->type == R_JSON_STRING)? strdup (role->str_value): strdup ("assistant");
	new_msg.content = (content && content->type == R_JSON_STRING)? strdup (content->str_value): NULL;
	new_msg.tool_call_id = NULL;
	new_msg.tool_calls = NULL;

	if (content_blocks && content_blocks->type == R_JSON_ARRAY && content_blocks->children.count > 0) {
		RList *cb = r2ai_content_blocks_new ();
		if (!cb) {
			r2ai_message_free (&new_msg);
			return false;
		}
		for (size_t i = 0; i < content_blocks->children.count; i++) {
			const RJson *block = r_json_item (content_blocks, i);
			if (!block) {
				continue;
			}
			R2AI_ContentBlock *dst = R_NEW0 (R2AI_ContentBlock);
			if (!dst) {
				r2ai_content_blocks_free (cb);
				r2ai_message_free (&new_msg);
				return false;
			}
			const RJson *type = r_json_get (block, "type");
			const RJson *data = r_json_get (block, "data");
			const RJson *thinking = r_json_get (block, "thinking");
			const RJson *signature = r_json_get (block, "signature");
			const RJson *text = r_json_get (block, "text");
			const RJson *id = r_json_get (block, "id");
			const RJson *name = r_json_get (block, "name");
			const RJson *input = r_json_get (block, "input");

			dst->type = (type && type->type == R_JSON_STRING)? strdup (type->str_value): NULL;
			dst->data = (data && data->type == R_JSON_STRING)? strdup (data->str_value): NULL;
			dst->thinking = (thinking && thinking->type == R_JSON_STRING)? strdup (thinking->str_value): NULL;
			dst->signature = (signature && signature->type == R_JSON_STRING)? strdup (signature->str_value): NULL;
			dst->text = (text && text->type == R_JSON_STRING)? strdup (text->str_value): NULL;
			dst->id = (id && id->type == R_JSON_STRING)? strdup (id->str_value): NULL;
			dst->name = (name && name->type == R_JSON_STRING)? strdup (name->str_value): NULL;
			dst->input = (input && input->type == R_JSON_STRING)? strdup (input->str_value): NULL;
			r_list_append (cb, dst);
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
			tc.name = (name && name->type == R_JSON_STRING)? name->str_value: NULL;
			tc.arguments = (arguments && arguments->type == R_JSON_STRING)? arguments->str_value: NULL;
			tc.id = (id && id->type == R_JSON_STRING)? id->str_value: NULL;

			if (!r2ai_msgs_add_tool_call (msgs, &tc)) {
				r2ai_message_free (&new_msg);
				return false;
			}
		}
	}

	return true;
}

R_API char *r2ai_msgs_to_json(const RList *msgs) {
	if (!msgs || r_list_empty (msgs)) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	RListIter *iter;
	const R2AI_Message *msg;
	r_list_foreach (msgs, iter, msg) {

		pj_o (pj); // Start message object

		// Add role
		pj_ks (pj, "role", msg->role? msg->role: "user");

		// Content is required for OpenAI API
		if (msg->content && *msg->content) {
			pj_ks (pj, "content", msg->content);
		} else if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
			pj_knull (pj, "content");
		} else {
			pj_ks (pj, "content", msg->content? msg->content: "");
		}

		if (msg->reasoning_content) {
			pj_ks (pj, "reasoning_content", msg->reasoning_content);
		}

		// Add tool_call_id if present
		if (msg->tool_call_id) {
			pj_ks (pj, "tool_call_id", msg->tool_call_id);
		}

		// Add tool_calls if present
		if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
			pj_k (pj, "tool_calls");
			pj_a (pj); // Start tool_calls array

			RListIter *iter;
			R2AI_ToolCall *tc;
			r_list_foreach (msg->tool_calls, iter, tc) {
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
				pj_ks (pj, "name", tc->name? tc->name: "");

				// Add arguments (required by OpenAI API)
				pj_ks (pj, "arguments", tc->arguments? tc->arguments: "{}");

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

R_API char *r2ai_msgs_to_anthropic_json(const RList *msgs) {
	if (!msgs || r_list_empty (msgs)) {
		return NULL;
	}

	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_a (pj); // Start array

	RListIter *iter;
	const R2AI_Message *msg;
	r_list_foreach (msgs, iter, msg) {
		pj_o (pj); // Start message object

		// Add role
		const char *role = msg->role? msg->role: "user";
		pj_ks (pj, "role", strcmp (role, "tool") == 0? "user": role);

		if (msg->content_blocks) {
			pj_ka (pj, "content"); // Start content array
			RListIter *iter;
			R2AI_ContentBlock *block;
			r_list_foreach (msg->content_blocks, iter, block) {
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
						pj_ko (pj, "input");
						pj_raw (pj, input_str);
						pj_end (pj);
						r_json_free (input_json);
					} else {
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

			if (msg->tool_calls && r_list_length (msg->tool_calls) > 0) {
				RListIter *iter;
				R2AI_ToolCall *tc;
				r_list_foreach (msg->tool_calls, iter, tc) {
					pj_o (pj); // Start tool_use content block
					pj_ks (pj, "type", "tool_use");
					pj_ks (pj, "id", tc->id? tc->id: "");
					pj_ks (pj, "name", tc->name? tc->name: "");

					// Create a non-const copy for r_json_parse
					char *arguments_copy = tc->arguments? strdup (tc->arguments): NULL;
					RJson *arguments = arguments_copy? r_json_parse (arguments_copy): NULL;

					pj_ko (pj, "input"); // Start input object
					if (arguments) {
						for (size_t k = 0; k < arguments->children.count; k++) {
							const RJson *arg = r_json_item (arguments, k);
							if (arg && arg->type == R_JSON_STRING) {
								pj_ks (pj, arg->key, arg->str_value);
							}
						}
						r_json_free (arguments);
					}
					free (arguments_copy);

					pj_end (pj); // End input object
					pj_end (pj); // End tool_use content block
				}
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
R_API void r2ai_delete_last_messages(RList *messages, int n) {
	if (!messages || r_list_length (messages) == 0) {
		return;
	}

	// If n is not specified or invalid, default to deleting the last message
	if (n <= 0) {
		n = 1;
	}

	// Make sure we don't try to delete more messages than exist
	int len = r_list_length (messages);
	if (n > len) {
		n = len;
	}

	// Pop the last n messages
	for (int i = 0; i < n; i++) {
		r_list_pop (messages);
	}
}
