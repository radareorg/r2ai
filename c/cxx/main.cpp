#include "common.h"

#include "llama.h"

#include <cassert>
#include <cinttypes>
#include <cmath>
#include <cstdio>
#include <string.h>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "common.cpp"
#include "sampling.cpp"

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
#include <signal.h>
#include <unistd.h>
#elif defined (_WIN32)
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <signal.h>
#endif

#if defined(_MSC_VER)
#pragma warning(disable: 4244 4267) // possible loss of data
#endif

// Abuse globals to make things easier to refactor this shitty code
static std::string path_session;
static llama_sampling_params *sparams;
static std::vector<llama_token> session_tokens;
static std::vector<llama_token> guidance_inp;
static int guidance_offset = 0;
static int original_prompt_len = 0;
static std::vector<llama_token> embd_inp;
static std::vector<llama_token> inp_pfx;
static std::vector<llama_token> inp_sfx;
static std::vector<llama_token> cml_pfx;
static std::vector<llama_token> cml_sfx;
static llama_context           ** g_ctx;
static llama_context * ctx_guidance = NULL;
static llama_model * model;
static llama_model ** g_model;
static gpt_params * g_params;
static std::vector<llama_token> * g_input_tokens;
static std::ostringstream       * g_output_ss;
size_t n_matching_session_tokens = 0;
static std::vector<llama_token> * g_output_tokens;
static llama_context * ctx;
static bool is_interacting = false;
static int n_ctx_train;
static int n_ctx;
static bool stdin_borken = false;


#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__)) || defined (_WIN32)
static void sigint_handler(int signo) {
	if (signo == SIGINT) {
		if (!is_interacting) {
			is_interacting = true;
		} else {
			// console::cleanup();
			printf("\n");
			llama_print_timings(*g_ctx);
			_exit(130);
		}
	}
}
#endif

static void null_log(ggml_log_level level, const char * text, void * user_data) {
    (void) level;
    (void) user_data;
    // LOG_TEE("%s", text);
}

static bool cxxreadline(std::string & line, bool multiline_input) {
#if defined(_WIN32)
	std::wstring wline;
	if (!std::getline(std::wcin, wline)) {
		// Input stream is bad or EOF received
		line.clear();
		GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
		return false;
	}

	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wline[0], (int)wline.size(), NULL, 0, NULL, NULL);
	line.resize(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, &wline[0], (int)wline.size(), &line[0], size_needed, NULL, NULL);
#else
	if (!std::getline(std::cin, line)) {
		// Input stream is bad or EOF received
		stdin_borken = true;
		line.clear();
		return false;
	}
#endif
	if (!line.empty()) {
		char last = line.back();
		if (last == '/') { // Always return control on '/' symbol
			line.pop_back();
			return false;
		}
		if (last == '\\') { // '\\' changes the default action
			line.pop_back();
			multiline_input = !multiline_input;
		}
	}
	line += '\n';

	// By default, continue input if multiline_input is set
	return multiline_input;
}

bool r2ai_llama_init(void) {
	llama_log_set(null_log, nullptr);
	// log_set_target(log_filename_generator("main", "log"));
	// log_dump_cmdline (argc, argv);
       sparams = &g_params->sparams;
	// TODO: Dump params ?
	//printf ("Params perplexity: %s\n", LOG_TOSTR(params.perplexity));

	// save choice to use color for later
	// (note for later: this is a slightly awkward choice)
#if 0
	console::init(params.simple_io, params.use_color);
	atexit([]() { console::cleanup(); });
	if (params.logits_all) {
		printf("\n************\n");
		printf("%s: please use the 'perplexity' tool for perplexity calculations\n", __func__);
		printf("************\n\n");

		return 0;
	}

	if (params.embedding) {
		printf("\n************\n");
		printf("%s: please use the 'embedding' tool for embedding calculations\n", __func__);
		printf("************\n\n");

		return 0;
	}
#endif

#if 0
	if (params.rope_freq_base != 0.0) {
		LOG_TEE("%s: warning: changing RoPE frequency base to %g.\n", __func__, params.rope_freq_base);
	}

	if (params.rope_freq_scale != 0.0) {
		LOG_TEE("%s: warning: scaling RoPE frequency by %g.\n", __func__, params.rope_freq_scale);
	}

	LOG_TEE("%s: build = %d (%s)\n",      __func__, LLAMA_BUILD_NUMBER, LLAMA_COMMIT);
	LOG_TEE("%s: built with %s for %s\n", __func__, LLAMA_COMPILER, LLAMA_BUILD_TARGET);
	LOG_TEE("%s: seed  = %u\n", __func__, g_params.seed);
#endif

#if 0
	std::mt19937 rng(params.seed);
	if (params.random_prompt) {
		params.prompt = gpt_random_prompt(rng);
	}
	printf ("%s: llama backend init\n", __func__);
#endif
	llama_backend_init (g_params->numa);

	g_model = &model;
	g_ctx = &ctx;

	// load the model and apply lora adapter, if any
	LOG ("%s: load the model and apply lora adapter, if any\n", __func__);
	std::tie(model, ctx) = llama_init_from_gpt_params (*g_params);
	if (sparams->cfg_scale > 1.f) {
		struct llama_context_params lparams = llama_context_params_from_gpt_params (*g_params);
		ctx_guidance = llama_new_context_with_model (model, lparams);
	}

	if (model == NULL) {
		LOG_TEE("%s: error: unable to load model\n", __func__);
		return 1;
	}

	n_ctx_train = llama_n_ctx_train (model);
	n_ctx = llama_n_ctx (ctx);
	LOG ("n_ctx: %d\n", n_ctx);

	if (n_ctx > n_ctx_train) {
		LOG_TEE("%s: warning: model was trained on only %d context tokens (%d specified)\n",
				__func__, n_ctx_train, n_ctx);
	}

	path_session = g_params->path_prompt_cache;

	const bool add_bos = llama_should_add_bos_token (model);
	//printf ("add_bos: %d\n", add_bos);

	if (g_params->interactive_first || g_params->instruct || g_params->chatml || !g_params->prompt.empty() || session_tokens.empty()) {
		//printf ("tokenize the prompt\n");
		if (g_params->chatml) {
			g_params->prompt = "<|im_start|>system\n" + g_params->prompt + "<|im_end|>";
		}
		embd_inp = ::llama_tokenize (ctx, g_params->prompt, add_bos, true);
	} else {
		//printf ("use session tokens\n");
		embd_inp = session_tokens;
	}

#if 0
	printf ("--> (%s)\n", params.prompt.c_str());
	printf ("prompt: \"%s\"\n", log_tostr(params.prompt));
	printf ("tokens: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, embd_inp).c_str());
#endif

	// Should not run without any tokens
	if (embd_inp.empty()) {
		embd_inp.push_back(llama_token_bos(model));
	//	printf ("embd_inp was considered empty and bos was added: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, embd_inp).c_str());
	}

	// Tokenize negative prompt
	if (ctx_guidance) {
		//printf ("cfg_negative_prompt: \"%s\"\n", log_tostr (sparams->cfg_negative_prompt));
		guidance_inp = ::llama_tokenize(ctx_guidance, sparams->cfg_negative_prompt, add_bos, true);
		//printf ("guidance_inp tokenized: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx_guidance, guidance_inp).c_str());
		std::vector<llama_token> original_inp = ::llama_tokenize(ctx, g_params->prompt, add_bos, true);
		// printf ("original_inp tokenized: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, original_inp).c_str());

		original_prompt_len = original_inp.size();
		guidance_offset = (int)guidance_inp.size() - original_prompt_len;
		// printf ("original_prompt_len: %s\n", log_tostr(original_prompt_len));
		// printf ("guidance_offset:     %s\n", log_tostr(guidance_offset));
	}

	if ((int) embd_inp.size() > n_ctx - 4) {
		LOG_TEE("%s: error: prompt is too long (%d tokens, max %d)\n", __func__, (int) embd_inp.size(), n_ctx - 4);
		return 1;
	}

	// debug message about similarity of saved session, if applicable
	if (!session_tokens.empty()) {
		for (llama_token id : session_tokens) {
			if (n_matching_session_tokens >= embd_inp.size() || id != embd_inp[n_matching_session_tokens]) {
				break;
			}
			n_matching_session_tokens++;
		}
#if 0
		if (params.prompt.empty() && n_matching_session_tokens == embd_inp.size()) {
			LOG_TEE("%s: using full prompt from session file\n", __func__);
		} else if (n_matching_session_tokens >= embd_inp.size()) {
			LOG_TEE("%s: session file has exact match for prompt!\n", __func__);
		} else if (n_matching_session_tokens < (embd_inp.size() / 2)) {
			LOG_TEE("%s: warning: session file has low similarity to prompt (%zu / %zu tokens); will mostly be reevaluated\n",
					__func__, n_matching_session_tokens, embd_inp.size());
		} else {
			LOG_TEE("%s: session file matches %zu / %zu tokens of prompt\n",
					__func__, n_matching_session_tokens, embd_inp.size());
		}
#endif

		// remove any "future" tokens that we might have inherited from the previous session
		llama_kv_cache_seq_rm(ctx, -1, n_matching_session_tokens, -1);
	}
#if 0
	LOGLN(
			"recalculate the cached logits (check): embd_inp.empty() %s, n_matching_session_tokens %zu, embd_inp.size() %zu, session_tokens.size() %zu, embd_inp.size() %zu",
			log_tostr(embd_inp.empty()), n_matching_session_tokens, embd_inp.size(), session_tokens.size(), embd_inp.size());

#endif
	// if we will use the cache for the full prompt without reaching the end of the cache, force
	// reevaluation of the last token token to recalculate the cached logits
	if (!embd_inp.empty() && n_matching_session_tokens == embd_inp.size() && session_tokens.size() > embd_inp.size()) {
#if 0
		LOGLN("recalculate the cached logits (do): session_tokens.resize( %zu )", embd_inp.size() - 1);
#endif

		session_tokens.resize(embd_inp.size() - 1);
	}

	// number of tokens to keep when resetting context
	if (g_params->n_keep < 0 || g_params->n_keep > (int) embd_inp.size() || g_params->instruct || g_params->chatml) {
		g_params->n_keep = (int)embd_inp.size();
	}

	// prefix & suffix for instruct mode
	inp_pfx = ::llama_tokenize(ctx, "\n\n### Instruction:\n\n", add_bos, true);
	inp_sfx = ::llama_tokenize(ctx, "\n\n### Response:\n\n",    false,   true);

#if 0
	printf ("inp_pfx: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, inp_pfx).c_str());
	printf ("inp_sfx: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, inp_sfx).c_str());
#endif

	// chatml prefix & suffix
	cml_pfx = ::llama_tokenize(ctx, "\n<|im_start|>user\n", add_bos, true);
	cml_sfx = ::llama_tokenize(ctx, "<|im_end|>\n<|im_start|>assistant\n", false, true);
#if 0
	printf ("cml_pfx: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, cml_pfx).c_str());
	printf ("cml_sfx: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, cml_sfx).c_str());
#endif
	// in instruct mode, we inject a prefix and a suffix to each input by the user
	if (g_params->instruct) {
		g_params->interactive_first = true;
		g_params->antiprompt.push_back("### Instruction:\n\n");
	}
	// similar for chatml mode
	else if (g_params->chatml) {
		g_params->interactive_first = true;
		g_params->antiprompt.push_back("<|im_start|>user\n");
	}

	// enable interactive mode if interactive start is specified
	if (g_params->interactive_first) {
		g_params->interactive = true;
	}

	if (g_params->interactive) {
#if 1
#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
		struct sigaction sigint_action;
		sigint_action.sa_handler = sigint_handler;
		sigemptyset (&sigint_action.sa_mask);
		sigint_action.sa_flags = 0;
		sigaction(SIGINT, &sigint_action, NULL);
#elif defined (_WIN32)
		auto console_ctrl_handler = +[](DWORD ctrl_type) -> BOOL {
			return (ctrl_type == CTRL_C_EVENT) ? (sigint_handler(SIGINT), true) : false;
		};
		SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(console_ctrl_handler), true);
#endif
#endif
#if 0
		if (!g_params->antiprompt.empty()) {
			for (const auto & antiprompt : g_params->antiprompt) {
			// 	LOG_TEE("Reverse prompt: '%s'\n", antiprompt.c_str());
				if (g_params->verbose_prompt) {
					auto tmp = ::llama_tokenize(ctx, antiprompt, false, true);
					for (int i = 0; i < (int) tmp.size(); i++) {
						LOG_TEE("%6d -> '%s'\n", tmp[i], llama_token_to_piece(ctx, tmp[i]).c_str());
					}
				}
			}
		}

		if (!g_params->input_prefix.empty()) {
			// LOG_TEE("Input prefix: '%s'\n", g_params->input_prefix.c_str());
			if (g_params->verbose_prompt) {
				auto tmp = ::llama_tokenize(ctx, g_params->input_prefix, true, true);
				for (int i = 0; i < (int) tmp.size(); i++) {
					LOG_TEE("%6d -> '%s'\n", tmp[i], llama_token_to_piece(ctx, tmp[i]).c_str());
				}
			}
		}

		if (!g_params->input_suffix.empty()) {
			// LOG_TEE("Input suffix: '%s'\n", g_params->input_suffix.c_str());
			if (g_params->verbose_prompt) {
				auto tmp = ::llama_tokenize(ctx, g_params->input_suffix, false, true);
				for (int i = 0; i < (int) tmp.size(); i++) {
					LOG_TEE("%6d -> '%s'\n", tmp[i], llama_token_to_piece(ctx, tmp[i]).c_str());
				}
			}
		}
#endif
	}
#if 0
	LOG_TEE("sampling: \n%s\n", llama_sampling_print(sparams).c_str());
	LOG_TEE("sampling order: \n%s\n", llama_sampling_order_print(sparams).c_str());
	LOG_TEE("generate: n_ctx = %d, n_batch = %d, n_predict = %d, n_keep = %d\n",
		n_ctx, g_params->n_batch, g_params->n_predict, g_params->n_keep);
#endif

	if (g_params->interactive) {
		is_interacting = g_params->interactive_first;
	}
	return true;
}

int main(int argc, char ** argv) {
	gpt_params params;
	if (!gpt_params_parse(argc, argv, params)) {
		return 1;
	}

	params.antiprompt.push_back("[INST]");
	params.input_prefix = "<s>[INST]";
	params.input_suffix = "[/INST]";
	params.interactive = true;
	params.model = "/tmp/mistral-7b-v0.1.Q2_K.gguf";
	// params.model = "/tmp/phi-2_Q4_K_M.gguf";
	params.n_predict = -1; // std::stoi(argv[i]);
	if (params.n_ctx != 0 && params.n_ctx < 8) {
		LOG_TEE("%s: warning: minimum context size is 8, using minimum size.\n", __func__);
		params.n_ctx = 8;
	}
#if R2
	params.seed = r_config_get_i (core->config, "r2ai.seed");
	if (params.seed == 0) {
		params.seed = LLAMA_DEFAULT_SEED;
	}
#else
	if (params.seed == LLAMA_DEFAULT_SEED) {
		params.seed = time(NULL);
	}
#endif

	g_params = &params;

	r2ai_llama_init ();

	bool is_antiprompt        = false;
	bool input_echo           = true;
	bool need_to_save_session = !path_session.empty() && n_matching_session_tokens < embd_inp.size();

	int n_past             = 0;
	int n_remain           = params.n_predict;
	int n_consumed         = 0;
	int n_session_consumed = 0;
	int n_past_guidance    = 0;

	std::vector<int>   input_tokens;  g_input_tokens  = &input_tokens;
	std::vector<int>   output_tokens; g_output_tokens = &output_tokens;
	std::ostringstream output_ss;     g_output_ss     = &output_ss;

	// the first thing we will do is to output the prompt, so set color accordingly
	// console::set_display(console::prompt);

	std::vector<llama_token> embd;
	std::vector<llama_token> embd_guidance;

	struct llama_sampling_context * ctx_sampling = llama_sampling_init(*sparams);

	while ((n_remain != 0 && !is_antiprompt) || params.interactive) {
		// predict
		if (!embd.empty()) {
			// Note: n_ctx - 4 here is to match the logic for commandline prompt handling via
			// --prompt or --file which uses the same value.
			int max_embd_size = n_ctx - 4;

			// Ensure the input doesn't exceed the context size by truncating embd if necessary.
			if ((int) embd.size() > max_embd_size) {
				const int skipped_tokens = (int) embd.size() - max_embd_size;
				embd.resize(max_embd_size);

				// console::set_display(console::error);
				printf("<<input too long: skipped %d token%s>>", skipped_tokens, skipped_tokens != 1 ? "s" : "");
				// console::set_display(console::reset);
				fflush(stdout);
			}

			// infinite text generation via context swapping
			// if we run out of context:
			// - take the n_keep first tokens from the original prompt (via n_past)
			// - take half of the last (n_ctx - n_keep) tokens and recompute the logits in batches
			if (n_past + (int) embd.size() + std::max<int>(0, guidance_offset) > n_ctx) {
				if (params.n_predict == -2) {
					LOG_TEE("\n\n%s: context full and n_predict == -%d => stopping\n", __func__, params.n_predict);
					break;
				}

				const int n_left    = n_past - params.n_keep - 1;
				const int n_discard = n_left/2;

				printf ("context full, swapping: n_past = %d, n_left = %d, n_ctx = %d, n_keep = %d, n_discard = %d\n",
						n_past, n_left, n_ctx, params.n_keep, n_discard);

				llama_kv_cache_seq_rm   (ctx, 0, params.n_keep + 1            , params.n_keep + n_discard + 1);
				llama_kv_cache_seq_shift(ctx, 0, params.n_keep + 1 + n_discard, n_past, -n_discard);

				n_past -= n_discard;

				if (ctx_guidance) {
					n_past_guidance -= n_discard;
				}

				printf ("after swap: n_past = %d, n_past_guidance = %d\n", n_past, n_past_guidance);

				printf ("embd: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, embd).c_str());

				printf ("clear session path\n");
				path_session.clear();
			}

			// try to reuse a matching prefix from the loaded session instead of re-eval (via n_past)
			if (n_session_consumed < (int) session_tokens.size()) {
				size_t i = 0;
				for ( ; i < embd.size(); i++) {
					if (embd[i] != session_tokens[n_session_consumed]) {
						session_tokens.resize(n_session_consumed);
						break;
					}

					n_past++;
					n_session_consumed++;

					if (n_session_consumed >= (int) session_tokens.size()) {
						++i;
						break;
					}
				}
				if (i > 0) {
					embd.erase(embd.begin(), embd.begin() + i);
				}
			}

			// evaluate tokens in batches
			// embd is typically prepared beforehand to fit within a batch, but not always
			if (ctx_guidance) {
				int input_size = 0;
				llama_token * input_buf = NULL;

				if (n_past_guidance < (int) guidance_inp.size()) {
					// Guidance context should have the same data with these modifications:
					//
					// * Replace the initial prompt
					// * Shift everything by guidance_offset
					embd_guidance = guidance_inp;
					if (embd.begin() + original_prompt_len < embd.end()) {
						embd_guidance.insert(
								embd_guidance.end(),
								embd.begin() + original_prompt_len,
								embd.end()
								);
					}

					input_buf  = embd_guidance.data();
					input_size = embd_guidance.size();

					printf ("guidance context: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, embd_guidance).c_str());
				} else {
					input_buf  = embd.data();
					input_size = embd.size();
				}

				for (int i = 0; i < input_size; i += params.n_batch) {
					int n_eval = std::min(input_size - i, params.n_batch);
					if (llama_decode(ctx_guidance, llama_batch_get_one(input_buf + i, n_eval, n_past_guidance, 0))) {
						LOG_TEE("%s : failed to eval\n", __func__);
						return 1;
					}

					n_past_guidance += n_eval;
				}
				// printf ("DECODE0 %d neval=%d\n", 0, 0);
			}

			for (int i = 0; i < (int) embd.size(); i += params.n_batch) {
				int n_eval = (int) embd.size() - i;
				if (n_eval > params.n_batch) {
					n_eval = params.n_batch;
				}

				// printf ("eval: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, embd).c_str());
				// printf ("DECODE1 %d embd=%d\n", n_eval, embd[i]);

				if (llama_decode(ctx, llama_batch_get_one(&embd[i], n_eval, n_past, 0))) {
					LOG_TEE("%s : failed to eval\n", __func__);
					return 1;
				}

				n_past += n_eval;

				// printf ("n_past = %d\n", n_past);
			}

			if (!embd.empty() && !path_session.empty()) {
				session_tokens.insert(session_tokens.end(), embd.begin(), embd.end());
				n_session_consumed = session_tokens.size();
			}
		}

		embd.clear();
		embd_guidance.clear();

		if ((int) embd_inp.size() <= n_consumed && !is_interacting) {
			const llama_token id = llama_sampling_sample(ctx_sampling, ctx, ctx_guidance);

			llama_sampling_accept(ctx_sampling, ctx, id, true);

			// printf ("last: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, ctx_sampling->prev).c_str());

			embd.push_back(id);
			// printf ("PUSH iBACK %d\n", id);

			// echo this to console
			input_echo = true;

			// decrement remaining sampling budget
			n_remain--;
		} else {
			// some user input remains from prompt or interaction, forward it to processing
			// printf ("embd_inp.size(): %d, n_consumed: %d\n", (int) embd_inp.size(), n_consumed);
			while ((int) embd_inp.size() > n_consumed) {
				// printf ("PUSH oBACK %d\n", embd_inp[n_consumed]);
				embd.push_back (embd_inp[n_consumed]);

				// push the prompt in the sampling context in order to apply repetition penalties later
				// for the prompt, we don't apply grammar rules
				llama_sampling_accept (ctx_sampling, ctx, embd_inp[n_consumed], false);

				n_consumed++;
				if ((int) embd.size() >= params.n_batch) {
					break;
				}
			}
		}

		// display text
		if (input_echo) {
			for (auto id : embd) {
				const std::string token_str = llama_token_to_piece(ctx, id);
				printf("%s", token_str.c_str());

				if (embd.size() > 1) {
					input_tokens.push_back(id);
				} else {
					output_tokens.push_back(id);
					output_ss << token_str;
				}
			}
			fflush (stdout);
		}
#if 0
		// reset color to default if there is no pending user input
		if (input_echo && (int) embd_inp.size() == n_consumed) {
			console::set_display(console::reset);
		}
#endif

		// if not currently processing queued inputs;
		if ((int) embd_inp.size() <= n_consumed) {
			// check for reverse prompt in the last n_prev tokens
			if (!params.antiprompt.empty()) {
				const int n_prev = 32;
				const std::string last_output = llama_sampling_prev_str(ctx_sampling, ctx, n_prev);

				is_antiprompt = false;
				// Check if each of the reverse prompts appears at the end of the output.
				// If we're not running interactively, the reverse prompt might be tokenized with some following characters
				// so we'll compensate for that by widening the search window a bit.
				for (std::string & antiprompt : params.antiprompt) {
					size_t extra_padding = params.interactive ? 0 : 2;
					size_t search_start_pos = last_output.length() > static_cast<size_t>(antiprompt.length() + extra_padding)
						? last_output.length() - static_cast<size_t>(antiprompt.length() + extra_padding)
						: 0;

					if (last_output.find(antiprompt, search_start_pos) != std::string::npos) {
						if (params.interactive) {
							is_interacting = true;
						}
						is_antiprompt = true;
						break;
					}
				}
			}

			// deal with end of text token in interactive mode
			if (llama_sampling_last (ctx_sampling) == llama_token_eos(model)) {
			//	printf ("found EOS token\n");

				if (params.interactive) {
					if (!params.antiprompt.empty()) {
						// tokenize and inject first reverse prompt
						const auto first_antiprompt = ::llama_tokenize(ctx, params.antiprompt.front(), false, true);
						embd_inp.insert(embd_inp.end(), first_antiprompt.begin(), first_antiprompt.end());
						is_antiprompt = true;
					}

					is_interacting = true;
					printf ("\n");
				} else if (params.instruct || params.chatml) {
					is_interacting = true;
				}
			}

			if (n_past > 0 && is_interacting) {
				if (params.instruct || params.chatml) {
					printf ("\n> ");
				}

				if (params.input_prefix_bos) {
					embd_inp.push_back(llama_token_bos(model));
				}

				std::string buffer;
				if (!params.input_prefix.empty()) {
					LOG ("appending input prefix: '%s'\n", params.input_prefix.c_str());
					// printf("(%s)", params.input_prefix.c_str());
				}

				// color user input only
				// console::set_display(console::user_input);

				std::string line;
				bool another_line = true;
				do {
					another_line = cxxreadline(line, params.multiline_input);
					buffer += line;
				} while (another_line);
				if (stdin_borken) {
					break;
				}

				// done taking input, reset color
				// console::set_display(console::reset);

				// Add tokens to embd only if the input buffer is non-empty
				// Entering a empty line lets the user pass control back
				if (buffer.length() > 1) {
					// printf ("POP BACK %d\n", buffer.length());
					// append input suffix if any
					if (!params.input_suffix.empty()) {
					//	printf ("appending input suffix: '%s'\n", params.input_suffix.c_str());
						//        printf("%s", params.input_suffix.c_str());
					}

					// printf ("buffer: '%s'\n", buffer.c_str());

					const size_t original_size = embd_inp.size();

					// instruct mode: insert instruction prefix
					if (params.instruct && !is_antiprompt) {
						n_consumed = embd_inp.size();
						embd_inp.insert(embd_inp.end(), inp_pfx.begin(), inp_pfx.end());
					}
					// chatml mode: insert user chat prefix
					if (params.chatml && !is_antiprompt) {
						n_consumed = embd_inp.size();
						embd_inp.insert(embd_inp.end(), cml_pfx.begin(), cml_pfx.end());
					}
					if (params.escape) {
						process_escapes(buffer);
					}

					const auto line_pfx = ::llama_tokenize(ctx, params.input_prefix, false, true);
					const auto line_inp = ::llama_tokenize(ctx, buffer,              false, false);
					const auto line_sfx = ::llama_tokenize(ctx, params.input_suffix, false, true);
					// printf ("input tokens: %s\n", LOG_TOKENS_TOSTR_PRETTY(ctx, line_inp).c_str());

					embd_inp.insert(embd_inp.end(), line_pfx.begin(), line_pfx.end());
					embd_inp.insert(embd_inp.end(), line_inp.begin(), line_inp.end());
					embd_inp.insert(embd_inp.end(), line_sfx.begin(), line_sfx.end());

					// instruct mode: insert response suffix
					if (params.instruct) {
						embd_inp.insert(embd_inp.end(), inp_sfx.begin(), inp_sfx.end());
					}
					// chatml mode: insert assistant chat suffix
					if (params.chatml) {
						embd_inp.insert(embd_inp.end(), cml_sfx.begin(), cml_sfx.end());
					}

					for (size_t i = original_size; i < embd_inp.size(); ++i) {
						const llama_token token = embd_inp[i];
						output_tokens.push_back(token);
						output_ss << llama_token_to_piece(ctx, token);
					}
					n_remain -= line_inp.size();
				}

				input_echo = false; // do not echo this again
			}

			if (n_past > 0) {
				if (is_interacting) {
					llama_sampling_reset(ctx_sampling);
				}
				is_interacting = false;
			}
		}

		// end of text token
		if (!embd.empty() && embd.back() == llama_token_eos(model) && !(params.instruct || params.interactive || params.chatml)) {
			printf (" [end of text]\n");
			break;
		}

		// In interactive mode, respect the maximum number of tokens and drop back to user input when reached.
		// We skip this logic when n_predict == -1 (infinite) or -2 (stop at context size).
		if (params.interactive && n_remain <= 0 && params.n_predict >= 0) {
			n_remain = params.n_predict;
			is_interacting = true;
		}
	}

	if (ctx_guidance) {
		llama_free (ctx_guidance);
	}
	llama_free (ctx);
	llama_free_model (model);

	llama_sampling_free (ctx_sampling);
	llama_backend_free ();

	return 0;
}
