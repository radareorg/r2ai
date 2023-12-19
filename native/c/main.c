// using examples/main/main.cpp as inspiration

#include <llama.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODEL_NAME "mistral-7b-v0.1.Q2_K.gguf"
#define MODEL_PATH "/Users/pancake/Library/Application Support/r2ai/models"

static void llama_log_cb(enum ggml_log_level level, const char *text, void *user_data) {
//	printf ("[r2ai] %s\n", text);
}

int main() {
	printf ("r2ai rewrite in C\n");
	llama_log_set (llama_log_cb, NULL);
	struct llama_context_params lparams = {0};
	lparams.n_batch = 32;
	lparams.n_threads = 2;
	lparams.n_threads_batch = 2;
	lparams.seed = -1;

	const char *model_path = MODEL_PATH "/" MODEL_NAME;
	struct llama_model_params mparams = llama_model_default_params ();
	struct llama_model *model = llama_load_model_from_file (model_path, mparams);
	struct llama_context *ctx = llama_new_context_with_model (model, lparams);

	int n_ctx_train = llama_n_ctx_train (model);
	int n_ctx = llama_n_ctx (ctx);
	printf ("%d %d\n", n_ctx, n_ctx_train);

	llama_set_rng_seed (ctx, 123);
	llama_token_bos (model);

	uint64_t msize = llama_model_size (model);
	fprintf (stderr, "Model Size: %lld\n", msize);
	char mdesc[256] = {0};
	if (llama_model_desc (model, mdesc, sizeof (mdesc))) {
		fprintf (stderr, "Model Description: %s\n", mdesc);
	}
	uint64_t mpara = llama_model_n_params (model);
	fprintf (stderr, "Model Parameters: %lld\n", mpara);

	fprintf (stderr, "Special Tokens:\n");
	fprintf (stderr, "BOS: %d\n", llama_token_bos (model));
	fprintf (stderr, "EOS: %d\n", llama_token_eos (model));
	fprintf (stderr, "NL:  %d\n", llama_token_nl (model));
	fprintf (stderr, "PFX:  %d\n", llama_token_prefix (model));
	fprintf (stderr, "MID:  %d\n", llama_token_middle (model));
	fprintf (stderr, "SUF:  %d\n", llama_token_suffix (model));
	fprintf (stderr, "EOT:  %d\n", llama_token_eot (model));


	const char *text = "Hello Lilly\n";
	int n_eval = 0;
	int n_past = 0;
	int token = 'h';
	bool add_bos = false;
	bool special = false;
	llama_token tokens[32] = {0};
	int n_max_tokens = 32;
	tokens[0] = llama_token_bos (model);
	int n_tokens = llama_tokenize (llama_get_model (ctx), text, strlen (text), &tokens[1], n_max_tokens, add_bos, special);
	n_tokens ++;
	int i;
	printf ("input tokens: %d\n", n_tokens);
	char piece[32] = {0};
	for (i = 0; i < n_tokens; i++) {
		memset (piece, 0, sizeof (piece));
		llama_token_to_piece (model, tokens[i], piece, sizeof (piece));
		printf ("%d %d %s\n", i, tokens[i], piece);
	}
	int32_t embd = 0;
	int32_t n_seq_max = 128;
	struct llama_batch res = llama_batch_init (n_tokens, embd, n_seq_max);
	res.n_tokens = n_tokens;
	res.token = calloc (n_tokens, sizeof (int32_t));
	memcpy (res.token, tokens, sizeof (int32_t) * n_tokens);
	// struct llama_batch res = llama_batch_get_one (tokens, n_tokens, 0, 0);
	printf ("PREDEC %d\n", res.pos[0]);
	if (llama_decode (ctx, res) != 0) {
		printf ("decode error\n");
	}
#if 0
	{
		struct llama_sampling_context *ctx_sampling = llama_sampling_init (params.sparams);
		int id = llama_sampling_sample (ctx_sampling, ctx, NULL, 0);
		llama_sampling_acept (ctx_sampling, ctx, id, true);
		llama_token_to_piece (ctx, id, piece, sizeof (piece));
		printf ("---> %s\n", piece);
	}
#endif
	printf ("POSDEC %d\n", res.pos[0]);
	printf ("output tokens: %d\n", res.n_tokens);
	// print response here
	for (i = 0; i < res.n_tokens + 4; i++) {
		memset (piece, 0, sizeof (piece));
		llama_token_to_piece (model, res.token[i], piece, sizeof (piece));
		printf ("%d %d %s\n", i, tokens[i], piece);
		// check of llama_token_eos (model);
	}
	llama_batch_free (res);
	llama_free_model (model);
	llama_free (ctx);
	return 0;
}
