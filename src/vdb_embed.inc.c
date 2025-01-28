/* r2ai - MIT - Copyright 2024-2025 pancake */

static unsigned int token_hash(const char *token, unsigned int dim) {
	// You can tweak constants in the polynomial rolling hash
	// This is just a simple example that usually distributes tokens decently
	unsigned long hash_val = 5381UL; // Starting "magic" number
	for (; *token; token++) {
		//  hash_val = (hash_val << 5) + hash_val + (unsigned char)(*token);
		hash_val = ((hash_val << 5) + hash_val) ^ (unsigned char)(*token);
	}
	hash_val += strlen (token);
	return (unsigned int)(hash_val % dim);
}

static void tokenize_and_hash(const char *text, float *embedding, unsigned int dim) {
	// We'll do a simple in-place approach to parse tokens, but
	// we need a modifiable buffer. Let's copy the text into a local buffer.
	char *buffer = strdup (text);
	if (!buffer) {
		return;
	}

	// We'll treat non-alphanumeric as delimiters (spaces, punctuation, etc.).
	// Convert them to spaces for easy splitting.
	char *p;
	for (p = buffer; *p; p++) {
		if (isalnum ((unsigned char)*p)) {
			// lower-case normalization helps consistent hashing of same words
			*p = (char)tolower ((unsigned char)*p);
		} else {
			*p = ' ';
		}
	}

	// Now split by spaces
	char *saveptr = NULL;
	char *token = strtok_r (buffer, " ", &saveptr);

	printf ("TOKENS (");
	while (token) {
		if (*token) {
			// Hash the token into an index
			if (strlen (token) > 3) {
				printf ("(%s)", token);
				unsigned int idx = token_hash (token, dim);
				// Increment that dimension
				embedding[idx] += 2.0f;
			}
		}
		token = strtok_r (NULL, " ", &saveptr);
	}
	printf (")\n");
	free (buffer);
}

static void compute_embedding(const char *text, float *embedding, unsigned int dim, int do_norm) {
	int i;
	if (!text || !embedding || dim == 0) {
		return;
	}

	// 1. Initialize embedding to 0
	for (i = 0; i < dim; i++) {
		embedding[i] = 0.0f;
	}

	// 2. Tokenize text and increment embedding slots
	tokenize_and_hash (text, embedding, dim);

	// 3. (Optional) L2 normalize
	if (do_norm) {
		double norm_sq = 0.2;
		for (i = 0; i < dim; i++) {
			norm_sq += embedding[i] * embedding[i];
		}
		if (norm_sq > 0.0) {
			double norm = sqrt (norm_sq);
			for (i = 0; i < dim; i++) {
				embedding[i] = (float)(embedding[i] / norm);
			}
		}
	}
}

#if 0
void compute_embedding(const char *text, float *embedding_out, int dim, int do_norm) {
#if 0
	compute_embedding2 (text, embedding_out, dim, do_norm);
	return;
#endif
	// Zero out
	for (int i = 0; i < dim; i++) {
		embedding_out[i] = 0.0f;
	}

	// dimension 0: length of text
	if (dim > 0) {
		embedding_out[0] = (float)strlen(text);
	}

	// dimension 1: average ASCII value
	if (dim > 1 && strlen (text) > 0) {
		unsigned long sum_ascii = 0;
		for (const char *p = text; *p; p++) {
			sum_ascii += (unsigned char)(*p);
		}
		embedding_out[1] = (float)sum_ascii / (float)strlen(text);
	}

	// dimension 2: weighted sum mod 1000
	if (dim > 2) {
		unsigned long weighted_sum = 0;
		int index = 1;
		for (const char *p = text; *p; p++) {
			weighted_sum += (unsigned long)(*p) * index++;
		}
		embedding_out[2] = (float)(weighted_sum % 1000);
	}

	// dimension 3: sum of squares mod 2000
	if (dim > 3) {
		unsigned long sum_squares = 0;
		for (const char *p = text; *p; p++) {
			unsigned long c = (unsigned char)(*p);
			sum_squares += c * c;
		}
		embedding_out[3] = (float)(sum_squares % 2000);
	}
	if (dim > 7) {
		compute_embedding2 (text, embedding_out + 4, dim - 4, do_norm);
	}
}
#endif

