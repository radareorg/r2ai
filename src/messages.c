/* r2ai - Copyright 2023-2026 dnakov, pancake */

#include "r2ai.h"

R_API void r2ai_tool_call_free(R2AI_ToolCall *tc) {
	if (tc) {
		free ((void *)tc->id);
		free ((void *)tc->name);
		free ((void *)tc->arguments);
		free (tc);
	}
}

static void block_free(R2AI_ContentBlock *b) {
	free (b->type);
	free (b->id);
	free (b->name);
	free (b->input);
	free (b->data);
	free (b->thinking);
	free (b->signature);
	free (b->text);
	free (b);
}

static R2AI_ContentBlock *block_dup(const R2AI_ContentBlock *b) {
	R2AI_ContentBlock *d = R_NEW0 (R2AI_ContentBlock);
	d->type = r_str_new (b->type);
	d->id = r_str_new (b->id);
	d->name = r_str_new (b->name);
	d->input = r_str_new (b->input);
	d->data = r_str_new (b->data);
	d->thinking = r_str_new (b->thinking);
	d->signature = r_str_new (b->signature);
	d->text = r_str_new (b->text);
	return d;
}

static R2AI_ToolCall *tc_dup(const R2AI_ToolCall *tc) {
	R2AI_ToolCall *d = R_NEW0 (R2AI_ToolCall);
	d->id = r_str_new (tc->id);
	d->name = r_str_new (tc->name);
	d->arguments = r_str_new (tc->arguments);
	return d;
}

R_API RList *r2ai_content_blocks_new(void) {
	return r_list_newf ((RListFree)block_free);
}

R_API void r2ai_message_fini(R2AI_Message *msg) {
	if (!msg) {
		return;
	}
	free (msg->role);
	free ((void *)msg->content);
	free (msg->reasoning_content);
	free (msg->tool_call_id);
	r_list_free (msg->tool_calls);
	r_list_free (msg->content_blocks);
	memset (msg, 0, sizeof (*msg));
}

R_API void r2ai_message_free(R2AI_Message *msg) {
	r2ai_message_fini (msg);
	free (msg);
}

R_IPI void r2ai_chat_response_free(R2AI_ChatResponse *res) {
	if (!res) {
		return;
	}
	r2ai_message_free ((R2AI_Message *)res->message);
	free ((void *)res->usage);
	free (res);
}

R_API void r2ai_conversation_init(R2AI_State *state) {
	if (state && !state->conversation) {
		state->conversation = r2ai_msgs_new ();
	}
}

R_API RList *r2ai_conversation_get(R2AI_State *state) {
	return state? state->conversation: NULL;
}

R_API RList *r2ai_msgs_new(void) {
	return r_list_newf ((RListFree)r2ai_message_free);
}

R_API void r2ai_msgs_free(RList *msgs) {
	r_list_free (msgs);
}

R_API void r2ai_conversation_free(R2AI_State *state) {
	if (state) {
		r_list_free (state->conversation);
		state->conversation = NULL;
	}
}

R_API void r2ai_msgs_clear(RList *msgs) {
	r_list_purge (msgs);
}

// append a deep copy of the message
R_API bool r2ai_msgs_add(RList *msgs, const R2AI_Message *msg) {
	if (!msgs || !msg) {
		return false;
	}
	R2AI_Message *m = R_NEW0 (R2AI_Message);
	m->role = r_str_new (msg->role);
	m->content = r_str_new (msg->content);
	m->reasoning_content = r_str_new (msg->reasoning_content);
	m->tool_call_id = r_str_new (msg->tool_call_id);
	if (msg->content_blocks) {
		m->content_blocks = r_list_clone (msg->content_blocks, (RListClone)block_dup);
		m->content_blocks->free = (RListFree)block_free;
	}
	m->tool_calls = msg->tool_calls
		? r_list_clone (msg->tool_calls, (RListClone)tc_dup)
		: r_list_new ();
	m->tool_calls->free = (RListFree)r2ai_tool_call_free;
	r_list_append (msgs, m);
	return true;
}

R_API char *r2ai_msgs_to_json(const RList *msgs, bool raw_tool_args) {
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

				// OpenAI wants arguments as a JSON-encoded string; Ollama wants a raw object.
				const char *a = R_STR_ISEMPTY (tc->arguments)? "{}": tc->arguments;
				pj_k (pj, "arguments");
				if (raw_tool_args) {
					pj_raw (pj, a);
				} else {
					pj_s (pj, a);
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

		// Circumvent Anthropic's allergy to system role messages
		const char *role = msg->role? msg->role: "user";
		bool is_system_message = !strcmp (role, "system");
		if (is_system_message) {
			role = "user";
		}
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
					pj_k (pj, "input");
					pj_raw (pj, block->input);
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
					if (is_system_message) {
						char *prefixed = r_str_newf ("SYSTEM INSTRUCTIONS: %s", msg->content);
						pj_ks (pj, "text", prefixed);
						free (prefixed);
					} else {
						pj_ks (pj, "text", msg->content);
					}
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

					// Insert the arguments directly as the input object
					pj_k (pj, "input");
					if (tc->arguments) {
						pj_raw (pj, tc->arguments);
					} else {
						pj_raw (pj, "{}");
					}
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
