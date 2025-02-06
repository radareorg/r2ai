/* r2ai - MIT - Copyright 2024-2025 pancake */

#include <r_util.h>

static void compute_embedding(RVDB *db, const char *text, float *embedding, unsigned int dim) {
	// Zero the embedding vector.
	memset (embedding, 0, dim * sizeof(float));

	/* --- Step 1. Tokenize the Document & Build a Local Frequency Table --- */
	// Make a modifiable copy of the text.
	char *buffer = strdup (text);
	if (!buffer) {
		return;
	}
	// We tokenize by whitespace (spaces, tabs, newlines).
	// Unlike previous versions, we do NOT force lowercase.
	char *saveptr;
	char *token = strtok_r (buffer, " \t\r\n", &saveptr);

	// Define a simple linked list structure for per-document token counts.
	typedef struct doc_token {
		char *token;
		int count;
		struct doc_token *next;
	} doc_token;

	doc_token *doc_tokens = NULL; // head of local token list

	while (token) {
		// Search the local list for this token.
		for (char *p = token; *p; p++) {
			if (!isalnum (*p)) {
				*p = ' ';
			} else {
				*p = (char)tolower ((unsigned char)*p);
			}
		}
		token = r_str_trim_head_ro (token);
		doc_token *cur = doc_tokens;
		doc_token *found = NULL;
		while (cur) {
			if (!strcmp (cur->token, token)) {
				found = cur;
				break;
			}
			cur = cur->next;
		}
		if (found) {
			found->count++;
		} else {
			// Add a new entry.
			doc_token *new_entry = (doc_token *)malloc(sizeof(doc_token));
			new_entry->token = strdup (token);
			r_str_trim (new_entry->token);
			new_entry->count = 1;
			new_entry->next = doc_tokens;
			doc_tokens = new_entry;
		}
		token = strtok_r (NULL, " \t\r\n", &saveptr);
	}
	free(buffer);

	/* --- Step 2. Update Global Document Frequencies --- */
	// Here we use the global definition of token_df (do not re-declare it locally).
	doc_token *dt = doc_tokens;
	while (dt) {
		token_df *cur_df = db->df_table;
		token_df *found_df = NULL;
		while (cur_df) {
			if (strcmp(cur_df->token, dt->token) == 0) {
				found_df = cur_df;
				break;
			}
			cur_df = cur_df->next;
		}
		if (found_df) {
			// Increment DF for this token (each document counts once per token).
	//		eprintf ("INC ---- %s\n", dt->token);
			found_df->df++;
		} else {
			// Create a new global DF entry.
			token_df *new_df = (token_df *)malloc(sizeof(token_df));
			new_df->token = strdup(dt->token);
			r_str_trim (new_df->token);
			new_df->df = 1;
	//		eprintf ("NEW ENTRY %s\n", dt->token);
			new_df->next = db->df_table;
			db->df_table = new_df;
		}
		dt = dt->next;
	}
	// Increment the total number of documents.
	db->total_docs++;

	/* --- Step 3. Compute TF-IDF for Each Token and Update the Embedding --- */
	dt = doc_tokens;
	while (dt) {
		// Compute term frequency: tf = 1 + log(token_count)
		float tf = 1.0f + log((float)dt->count);
		// Lookup df for dt->token in the global table.
		token_df *cur_df = db->df_table;
		int df_value = 0;
		while (cur_df) {
			if (strcmp(cur_df->token, dt->token) == 0) {
				cur_df->df += 0.1f;
				df_value = cur_df->df;
				break;
			}
			cur_df = cur_df->next;
		}
		// Compute inverse document frequency: idf = log((total_docs + 1) / (df + 1)) + 1
		float idf = log(((float)db->total_docs + 1.0f) / ((float)df_value + 1.0f)) + 1.0f;
		float weight = tf * idf;

		// Compute the hash for the token (using a simple polynomial rolling hash).
		unsigned int hash = 0;
		for (int i = 0; dt->token[i]; i++) {
			hash = hash * 31 + (unsigned char)dt->token[i];
		}
		unsigned int index = hash % dim;
		// Add the TF-IDF weight to the appropriate bucket.
		embedding[index] += weight;
		printf ("TOK %s = %f %f = %f\n", dt->token, tf, idf, weight);

		dt = dt->next;
	}

	/* Free the per-document token list. */
	dt = doc_tokens;
	while (dt) {
		doc_token *next = dt->next;
		free(dt->token);
		free(dt);
		dt = next;
	}

	/* --- Step 4. L2 Normalize the Embedding --- */
	double norm_sq = 0.0;
	for (unsigned int i = 0; i < dim; i++) {
		norm_sq += embedding[i] * embedding[i];
	}
	if (norm_sq > 0.0) {
		double norm = sqrt(norm_sq);
		for (unsigned int i = 0; i < dim; i++) {
			embedding[i] /= norm;
		}
	}
}
