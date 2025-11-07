/* r2ai wizard - Copyright 2025 pancake */

#define R_LOG_ORIGIN "r2ai_wizard"

#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include "r2ai.h"
#include "r2ai_priv.h"

static const char *clippy_messages[] = {
	"🪄 Abracadabra! Let's summon some AI magic!",
	"🔮 Crystal ball says... you need r2ai setup!",
	"⚡ Powering up the reverse-engineering spells...",
	"🎩 Pulling rabbits out of the binary hat!",
	"🌟 Twinkling with AI-powered insights!",
	"🚀 Launching into the AI dimension!",
	"💫 Casting binary analysis enchantments!",
	"🎯 Targeting the perfect AI setup!",
	"🔓 Unlocking the secrets of the binaries!",
	"🌈 Painting rainbows on your disassembly!",
	"⭐ You're not just reversing binaries — you're reverse-engineering reality!",
	"🎪 Welcome to the greatest AI show in radare2!",
	"🦄 Riding unicorns through the code matrix!",
	"🎨 Painting masterpieces with binary brushes!",
	"🌊 Surfing the waves of artificial intelligence!",
	"🎭 Masking the complexity, revealing the simplicity!",
	"🔥 Burning through the binary fog!",
	"⚗️ Alchemizing bytes into understanding!",
	"🎪 Step right up! The AI circus is in town!",
	"🌟 Making binary magic happen!"
};

static const char *wizard_tips[] = {
	"Only those who understand the bytes will master the bits.",
	"With great disassembly comes great responsibility.",
	"AI can read disassembly faster than elves read runes — but don't trust it blindly!",
	"A function without comments is a spell without meaning.",
	"Remember, young hacker — local models don't leak secrets!",
	"The force is strong with this binary analyzer.",
	"In AI we trust, but verify we must!",
	"Every binary tells a story, let AI be your translator.",
	"Debugging is like detective work, AI is your Watson.",
	"May the source be with you, always!"
};

static void show_clippy_message(RCore *core, const char *message) {
	r_cons_clear00 (core->cons);
	char *cmd = r_str_newf ("?E %s", message);
	r_core_cmd_call (core, cmd);
	free (cmd);
	r_cons_flush (core->cons);
}

static void show_progress_bar(RCore *core, const char *message, int current, int total) {
	int percent = (current * 100) / total;
	r_print_progressbar (core->print, percent, 80, message);
}

static const char *get_random_clippy_message(void) {
	return clippy_messages[rand () % (sizeof (clippy_messages) / sizeof (clippy_messages[0]))];
}

static const char *get_random_wizard_tip(void) {
	return wizard_tips[rand () % (sizeof (wizard_tips) / sizeof (wizard_tips[0]))];
}

static bool wizard_step_intro(RCore *core) {
	show_clippy_message (core, get_random_clippy_message ());
	r_cons_printf (core->cons,
		"\n"
		"🪄 Hi, I'm r2clippy, your reverse-engineering wizard assistant!\n"
		"🎯 I'll help you summon the power of AI inside radare2 (and even outside it).\n"
		"🚀 Let's start with a few spells... ehm, setup steps!\n\n"
		"%s\n\n",
		get_random_wizard_tip ());

	return r_cons_yesno (core->cons, 'y', "Ready to begin your AI journey? (Y/n)");
}

static bool wizard_step_setup(RCore *core) {
	show_clippy_message (core, "⚙️ Configuration time! Let's tune those AI settings!");

	r_cons_printf (core->cons,
		"\n"
		"🔧 First things first - let's make sure you have the latest r2ai!\n"
		"💡 It's good practice to update r2 and r2ai frequently for the latest fixes.\n\n"
		"Run this command to update: r2pm -Uci r2ai\n\n");

	if (r_cons_yesno (core->cons, 'y', "Have you updated r2ai recently? (Y/n)")) {
		show_progress_bar (core, "Checking updates...", 1, 3);
		r_sys_sleep (1);
		show_progress_bar (core, "Checking updates...", 2, 3);
		r_sys_sleep (1);
		show_progress_bar (core, "Checking updates...", 3, 3);
		r_sys_sleep (1);
		r_cons_printf (core->cons, "\n");
	}

	r_cons_printf (core->cons,
		"\n"
		"🤖 What's a Provider? It's the AI service you'll use (OpenAI, Anthropic, etc.)\n"
		"🧠 What's a Model? It's the specific AI brain (GPT-4, Claude, Gemma, etc.)\n\n"
		"📋 Try these commands to explore:\n"
		"   r2ai -p?  # List available providers\n"
		"   r2ai -m?  # List available models\n\n"
		"💬 Type 'shell' to enter r2ai shell mode, 'back' to return to wizard\n\n");

	if (r_cons_yesno (core->cons, 'y', "Want to skip API key setup for now? (Y/n)")) {
		return true;
	}

	R_API bool r2ai_wizard_isfirsttime (void) {
		char *ready_file = r_str_home (".config/r2ai/.ready");
		if (r_file_exists (ready_file)) {
			free (ready_file);
			return false;
		}

		// Create directory and touch the file
		char *config_dir = r_str_home (".config/r2ai");
		r_sys_mkdirp (config_dir);
		free (config_dir);

		int fd = r_sandbox_open (ready_file, O_CREAT | O_WRONLY, 0644);
		if (fd != -1) {
			close (fd);
		}
		free (ready_file);

		return true;
	}

	show_clippy_message (core, "🔑 Time to configure those API keys!");
	r_cons_printf (core->cons, "\nOpening API key configuration...\n");
	r_core_cmd_call (core, "r2ai -K");

	return true;
}

static bool wizard_step_basic_usage(RCore *core) {
	show_clippy_message (core, "🧩 Let's learn the basics of AI-powered reversing!");

	r_cons_printf (core->cons,
		"\n"
		"💬 Basic Chat Mode:\n"
		"   r2ai what's your name\n"
		"   r2ai explain this function\n\n"
		"🤖 Auto Mode - Your AI assistant can interact with r2 automatically!\n"
		"   r2ai -a tell me the architecture of this binary\n"
		"   r2ai -a find all strings in this program\n\n"
		"✨ Auto Mode features:\n"
		"   • AI can run r2 commands for you\n"
		"   • Perfect for learning r2 commands\n"
		"   • Great for complex analysis tasks\n"
		"   • You'll be asked to confirm actions\n\n");

	if (r_cons_yesno (core->cons, 'y', "Want to try a basic chat test? (Y/n)")) {
		show_clippy_message (core, "🧪 Testing the AI connection...");
		r_cons_printf (core->cons, "\nTry: r2ai what's your name\n");
		r_cons_printf (core->cons, "Type 'shell' to enter r2ai mode, then 'back' to continue\n");

		while (true) {
			r_cons_printf (core->cons, "r2ai-wizard> ");
			const char *line = r_line_readline (core->cons);
			if (!line) {
				break;
			}

			if (r_str_startswith (line, "shell")) {
				r_cons_printf (core->cons, "Entering r2ai shell mode (type 'exit' to return)...\n");
				r_core_cmd_call (core, "r2ai -r");
			} else if (r_str_startswith (line, "back")) {
				break;
			} else if (r_str_startswith (line, "skip")) {
				break;
			}
		}
	}

	return true;
}

static bool wizard_step_decompilation(RCore *core) {
	show_clippy_message (core, "🧱 Master the art of AI-powered decompilation!");

	r_cons_printf (core->cons,
		"\n"
		"🔍 Decompilation with AI:\n"
		"   r2ai -d                    # Decompile current function\n"
		"   r2ai -d explain this       # Ask about current function\n"
		"   r2ai -dr                   # Recursive decompilation\n\n"
		"🎛️ Advanced decompilation:\n"
		"   r2ai -e cmds=pdc,pdg,pdd   # Use multiple decompilers as input\n\n"
		"🏠 Recommended local models for decompilation:\n"
		"   • gpt-oss:20b              # Open source, good balance\n"
		"   • gemma3:12b               # Google's model\n"
		"   • granite:8b               # IBM's model\n\n"
		"☁️ Online services (better quality):\n"
		"   • OpenAI (GPT-4, GPT-3.5)\n"
		"   • Anthropic (Claude)\n"
		"   • Google (Gemini)\n"
		"   • Mistral, Groq, and more!\n\n");

	return r_cons_yesno (core->cons, 'y', "Ready to decompile like a wizard? (Y/n)");
}

static bool wizard_step_plugins(RCore *core) {
	show_clippy_message (core, "💥 Discover more AI-powered tools!");

	r_cons_printf (core->cons,
		"\n"
		"🔮 Other amazing plugins:\n\n"
		"📜 decai:\n"
		"   • Pure JavaScript decompilation plugin\n"
		"   • Focused specifically on decompilation tasks\n"
		"   • Lightweight and fast\n\n"
		"🔧 r2mcp:\n"
		"   • Model Context Protocol integration\n"
		"   • Lets AI agents use r2 as a tool\n"
		"   • Advanced automation possibilities\n\n"
		"🌟 These plugins work great alongside r2ai!\n\n");

	return true;
}

static bool wizard_step_tasks(RCore *core) {
	show_clippy_message (core, "🧰 Level up your reversing game!");

	r_cons_printf (core->cons,
		"\n"
		"🎯 Challenge yourself with these tasks:\n\n"
		"🔓 Binary Analysis:\n"
		"   r2ai -a find the xor key\n"
		"   r2ai -a patch the binary to skip password check\n"
		"   r2ai -a identify the encryption algorithm\n\n"
		"📚 Learning Path:\n"
		"   Level 1: r2ai -a name all imported functions\n"
		"   Level 2: r2ai -a find the main decryption routine\n"
		"   Level 3: r2ai -a summarize the binary in one sentence\n"
		"   Level 4: r2ai -a write an r2 script from AI output\n"
		"   Level 5: Build your own AI plugin that uses r2pipe!\n\n"
		"🎮 Game Modes:\n"
		"   • Mystery Mode: Get cryptic clues instead of answers\n"
		"   • Mentor Mode: Explain the disassembly yourself\n"
		"   • Challenge Mode: Complete tasks and get scored!\n\n");

	return r_cons_yesno (core->cons, 'y', "Ready to tackle these challenges? (Y/n)");
}

static bool wizard_step_followup(RCore *core) {
	show_clippy_message (core, "🔮 The journey continues...");

	r_cons_printf (core->cons,
		"\n"
		"🌟 Keep the magic going:\n\n"
		"💬 Join the community:\n"
		"   • r2con videos - Watch talks from reverse engineers\n"
		"   • radare2 Discord - Chat with other wizards\n"
		"   • GitHub discussions - Share your discoveries\n\n"
		"📚 Continue learning:\n"
		"   • Try different models and providers\n"
		"   • Experiment with custom prompts\n"
		"   • Create your own AI workflows\n\n"
		"✨ Remember: %s\n\n",
		get_random_wizard_tip ());

	r_cons_printf (core->cons,
		"🎉 Congratulations! You've completed the r2ai wizard!\n"
		"🪄 You're now ready to reverse-engineer with AI magic!\n\n");

	return true;
}

R_API bool r2ai_wizard(RCore *core) {
	if (!core) {
		return false;
	}

	r_cons_printf (core->cons, "\n");
	show_progress_bar (core, "Summoning r2clippy...", 1, 5);
	r_sys_sleep (1);
	show_progress_bar (core, "Summoning r2clippy...", 2, 5);
	r_sys_sleep (1);
	show_progress_bar (core, "Summoning r2clippy...", 3, 5);
	r_sys_sleep (1);
	show_progress_bar (core, "Summoning r2clippy...", 4, 5);
	r_sys_sleep (1);
	show_progress_bar (core, "Summoning r2clippy...", 5, 5);
	r_sys_sleep (1);
	r_cons_printf (core->cons, "\n\n");

	if (!wizard_step_intro (core)) {
		return false;
	}

	if (!wizard_step_setup (core)) {
		return false;
	}

	if (!wizard_step_basic_usage (core)) {
		return false;
	}

	if (!wizard_step_decompilation (core)) {
		return false;
	}

	if (!wizard_step_plugins (core)) {
		return false;
	}

	if (!wizard_step_tasks (core)) {
		return false;
	}

	wizard_step_followup (core);

	show_clippy_message (core, "🎊 Wizard complete! Go forth and reverse!");
	r_cons_printf (core->cons, "\nPress Enter to exit the wizard...\n");
	r_line_readline (core->cons);

	return true;
}

R_API bool r2ai_wizard_isfirsttime(void) {
	char *ready_file = r_str_home (".config/r2ai/.ready");
	if (r_file_exists (ready_file)) {
		free (ready_file);
		return false;
	}

	// Create directory and touch the file
	char *config_dir = r_str_home (".config/r2ai");
	r_sys_mkdirp (config_dir);
	free (config_dir);

	int fd = r_sandbox_open (ready_file, O_CREAT | O_WRONLY, 0644);
	if (fd != -1) {
		close (fd);
	}
	free (ready_file);

	return true;
}
