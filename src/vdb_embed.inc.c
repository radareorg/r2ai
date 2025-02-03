/* r2ai - MIT - Copyright 2024-2025 pancake */

#if 0
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

//	printf ("TOKENS (");
	while (token) {
		if (*token) {
			// Hash the token into an index
			if (strlen (token) > 3) {
//				printf ("(%s)", token);
				unsigned int idx = token_hash (token, dim);
				// Increment that dimension
				embedding[idx] += 2.0f;
			}
		}
		token = strtok_r (NULL, " ", &saveptr);
	}
//	printf (")\n");
	free (buffer);
}
#endif

static void compute_embedding(const char *text, float *embedding, unsigned int dim, int do_norm) {
	memset(embedding, 0, dim * sizeof(float));
	char buffer[1024];
	strncpy(buffer, text, sizeof(buffer) - 1);
	buffer[sizeof(buffer) - 1] = '\0';

	char *token = strtok(buffer, " ");
	while (token) {
		// Convert token to lowercase
		for (char *p = token; *p; p++) *p = tolower(*p);

		// Hash token using a polynomial rolling hash
		unsigned int hash = 0;
		for (int i = 0; token[i]; i++) {
			hash = hash * 31 + token[i];
		}
		unsigned int index = hash % dim;

		// Apply log-scaled term frequency instead of full TF-IDF
		embedding[index] += 1.0f;

		token = strtok(NULL, " ");
	}
	Vector v = {
		.data = embedding,
		.dim = dim
	};
	vector_norm (&v);
	// 3. (Optional) L2 normalize
	if (do_norm) {
		int i;
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
