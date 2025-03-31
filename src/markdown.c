#include <r_core.h>
#include <r_cons.h>
#include <r_types.h>
#include <r_util.h>
#include <string.h>
#include <ctype.h>
#include "markdown.h"

typedef enum {
    NORMAL,
    BOLD,
    ITALIC,
    CODE,
    STRIKE
} MarkdownState;

// Global theme instance
static RMarkdownTheme current_theme;
static bool theme_initialized = false;

// Set default theme values
R_API RMarkdownTheme r2ai_markdown_theme_default(void) {
    RMarkdownTheme theme = {
        // Text styling
        .bold = "\x1b[1m",                // Bold
        .italic = "\x1b[3m",              // Italic
        .strike = "\x1b[9m",              // Strikethrough
        .code_inline = "\x1b[48;5;236m",  // Dark gray background for inline code
        .code_block = "\x1b[48;5;235m",   // Slightly darker gray for code blocks
        
        // Heading colors
        .heading1 = "\x1b[1;4;31m",      // Bold, underlined, red
        .heading2 = "\x1b[1;4;32m",      // Bold, underlined, green
        .heading3 = "\x1b[1;4;33m",      // Bold, underlined, yellow
        .heading4 = "\x1b[1;4;34m",      // Bold, underlined, blue
        .heading5 = "\x1b[1;4;35m",      // Bold, underlined, magenta
        .heading6 = "\x1b[1;4;36m",      // Bold, underlined, cyan
        
        // List items
        .list_bullet = "• ",            // Bullet character
        .list_number = "\x1b[1m%s.\x1b[0m ", // Bold number
        
        // Checkbox states
        .checkbox_checked = "\x1b[32m[✓]\x1b[0m ",   // Green checkmark
        .checkbox_unchecked = "\x1b[90m[ ]\x1b[0m ", // Gray empty box
        
        // Reset code
        .reset = "\x1b[0m"
    };
    return theme;
}

// Initialize theme if not already done
static void ensure_theme_initialized(void) {
    if (!theme_initialized) {
        current_theme = r2ai_markdown_theme_default();
        theme_initialized = true;
    }
}

// Set a custom theme
R_API void r2ai_markdown_set_theme(const RMarkdownTheme *theme) {
    if (!theme) {
        current_theme = r2ai_markdown_theme_default();
    } else {
        current_theme = *theme;
    }
    theme_initialized = true;
}

// Get the current theme
R_API const RMarkdownTheme *r2ai_markdown_get_theme(void) {
    ensure_theme_initialized();
    return &current_theme;
}

static void append_formatted(RStrBuf *sb, const char *text, int len, MarkdownState state) {
    ensure_theme_initialized();
    
    switch (state) {
    case BOLD:
        r_strbuf_append(sb, current_theme.bold);
        r_strbuf_append_n(sb, text, len);
        r_strbuf_append(sb, current_theme.reset);
        break;
    case ITALIC:
        r_strbuf_append(sb, current_theme.italic);
        r_strbuf_append_n(sb, text, len);
        r_strbuf_append(sb, current_theme.reset);
        break;
    case CODE:
        r_strbuf_append(sb, current_theme.code_inline);
        r_strbuf_append_n(sb, text, len);
        r_strbuf_append(sb, current_theme.reset);
        break;
    case STRIKE:
        r_strbuf_append(sb, current_theme.strike);
        r_strbuf_append_n(sb, text, len);
        r_strbuf_append(sb, current_theme.reset);
        break;
    default:
        r_strbuf_append_n(sb, text, len);
        break;
    }
}

// Count leading spaces for indentation level
static int count_indent(const char *str) {
    int count = 0;
    while (*str == ' ' || *str == '\t') {
        count += (*str == '\t') ? 4 : 1;
        str++;
    }
    return count;
}

R_API char *r2ai_markdown(const char *markdown) {
    if (!markdown) {
        return NULL;
    }

    ensure_theme_initialized();
    
    RStrBuf *sb = r_strbuf_new("");
    if (!sb) {
        return NULL;
    }

    const char *p = markdown;
    const char *start = p;
    MarkdownState state = NORMAL;
    int in_code_block = 0;
    int line_start = 1;
    int indent_level = 0;

    while (*p) {
        // Handle code blocks
        if (line_start && p[0] == '`' && p[1] == '`' && p[2] == '`') {
            p += 3;
            in_code_block = !in_code_block;
            if (in_code_block) {
                // Add padding for full-width code blocks
                r_strbuf_appendf(sb, "%s\033[K", current_theme.code_block);
                
                // Skip language specifier if present
                while (*p && *p != '\n') p++;
                
            } else {
                r_strbuf_appendf(sb, "%s\n", current_theme.reset);
            }
            start = p;
            continue;
        }

        if (in_code_block) {
            if (*p == '\n') {
                r_strbuf_append_n(sb, start, p - start);
                // Add the \033[K (EL - Erase in Line) sequence to extend the background to the end of line
                r_strbuf_appendf(sb, "\n%s\033[K", current_theme.code_block);
                start = p + 1;
                line_start = 1;
            }
            p++;
            continue;
        }

        // Handle headings
        if (line_start && *p == '#') {
            int level = 0;
            while (*p == '#' && level < 6) {
                level++;
                p++;
            }
            
            if (*p == ' ') {
                p++; // Skip space after #
                start = p;
                
                // Find end of heading (newline)
                const char *heading_end = strchr(p, '\n');
                if (!heading_end) heading_end = p + strlen(p);
                
                // Add heading with appropriate size
                switch (level) {
                case 1:
                    r_strbuf_append(sb, current_theme.heading1);
                    break;
                case 2:
                    r_strbuf_append(sb, current_theme.heading2);
                    break;
                case 3:
                    r_strbuf_append(sb, current_theme.heading3);
                    break;
                case 4:
                    r_strbuf_append(sb, current_theme.heading4);
                    break;
                case 5:
                    r_strbuf_append(sb, current_theme.heading5);
                    break;
                case 6:
                    r_strbuf_append(sb, current_theme.heading6);
                    break;
                default:
                    r_strbuf_append(sb, current_theme.heading1);
                    break;
                }
                
                r_strbuf_append_n(sb, start, heading_end - start);
                r_strbuf_appendf(sb, "%s\n", current_theme.reset);
                
                if (*heading_end) {
                    p = heading_end + 1;
                } else {
                    p = heading_end;
                }
                start = p;
                line_start = (*p == '\n');
                continue;
            } else {
                // Not a proper heading, revert
                p = start;
            }
        }

        // Process lines at the start of the line
        if (line_start) {
            // Track indentation for nested lists
            indent_level = count_indent(p);
            const char *indent_end = p + indent_level;
            
            // Skip the indent spaces
            if (indent_level > 0) {
                append_formatted(sb, start, p - start, state);
                for (int i = 0; i < indent_level; i++) {
                    r_strbuf_append(sb, " ");
                }
                p = indent_end;
                start = p;
            }
            
            // Handle bullet lists
            if (*p == '-' && p[1] == ' ') {
                append_formatted(sb, start, p - start, state);
                r_strbuf_append(sb, current_theme.list_bullet);
                p += 2;
                start = p;
                line_start = 0;
                continue;
            }
            
            // Handle numbered lists (1., 2., etc.)
            if (isdigit(*p)) {
                const char *digit_start = p;
                while (isdigit(*p)) p++;
                
                if (*p == '.' && p[1] == ' ') {
                    append_formatted(sb, start, digit_start - start, state);
                    int num_len = p - digit_start;
                    char num_buf[16] = {0};
                    r_str_ncpy(num_buf, digit_start, num_len < 15 ? num_len + 1 : 15);
                    
                    // Use the actual number from markdown and format it
                    char formatted_number[32];
                    snprintf(formatted_number, sizeof(formatted_number), 
                             current_theme.list_number, num_buf);
                    r_strbuf_append(sb, formatted_number);
                    
                    p += 2; // Skip ". "
                    start = p;
                    line_start = 0;
                    continue;
                } else {
                    p = digit_start; // Not a numbered list, revert
                }
            }
            
            // Handle checklists
            if ((*p == '[' && (p[1] == ' ' || p[1] == 'x') && p[2] == ']' && p[3] == ' ')) {
                append_formatted(sb, start, p - start, state);
                
                if (p[1] == 'x') {
                    r_strbuf_append(sb, current_theme.checkbox_checked);
                } else {
                    r_strbuf_append(sb, current_theme.checkbox_unchecked);
                }
                
                p += 4; // Skip "[ ] " or "[x] "
                start = p;
                line_start = 0;
                continue;
            }
        }

        // Handle inline formatting
        if (*p == '*' || *p == '_' || *p == '`' || *p == '~') {
            char marker = *p;
            int double_marker = (p[1] == marker);
            
            // Check for opening or closing marker
            if (p > markdown && !isalnum(*(p-1)) && isalnum(p[1 + double_marker])) {
                // Opening marker
                if (p > start) {
                    append_formatted(sb, start, p - start, state);
                }
                p += double_marker ? 2 : 1;
                start = p;
                
                if (double_marker && marker == '*') {
                    state = BOLD;
                } else if (marker == '*' || marker == '_') {
                    state = ITALIC;
                } else if (marker == '`') {
                    state = CODE;
                } else if (double_marker && marker == '~') {
                    state = STRIKE;
                }
            } else if (p > markdown && isalnum(*(p-1)) && !isalnum(p[1 + double_marker])) {
                // Closing marker
                append_formatted(sb, start, p - start, state);
                p += double_marker ? 2 : 1;
                start = p;
                state = NORMAL;
            } else {
                p++;
            }
        } else if (*p == '\n') {
            append_formatted(sb, start, p - start, state);
            r_strbuf_append(sb, "\n");
            p++;
            start = p;
            line_start = 1;
            state = NORMAL; // Reset state at newline
        } else {
            p++;
            line_start = 0;
        }
    }

    // Handle any remaining text
    if (p > start) {
        append_formatted(sb, start, p - start, state);
    }

    char *result = r_strbuf_drain(sb);
    return result;
} 