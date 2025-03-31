#ifndef R2_MARKDOWN_H
#define R2_MARKDOWN_H

#include <r_types.h>

/* Theme configuration for markdown rendering */
typedef struct r_markdown_theme_t {
    // Text styling
    const char *bold;             // Bold text
    const char *italic;           // Italic text
    const char *strike;           // Strikethrough text
    const char *code_inline;      // Inline code
    const char *code_block;       // Code block background
    
    // Heading colors (h1-h6)
    const char *heading1;
    const char *heading2;
    const char *heading3;
    const char *heading4;
    const char *heading5;
    const char *heading6;
    
    // List items
    const char *list_bullet;      // Bullet character for unordered lists
    const char *list_number;      // Number formatting for ordered lists
    
    // Checkbox states
    const char *checkbox_checked;
    const char *checkbox_unchecked;
    
    // Reset code
    const char *reset;
} RMarkdownTheme;

/* Default built-in theme */
R_API RMarkdownTheme r2ai_markdown_theme_default(void);

/* Set a custom theme for markdown rendering */
R_API void r2ai_markdown_set_theme(const RMarkdownTheme *theme);

/* Get the current theme */
R_API const RMarkdownTheme *r2ai_markdown_get_theme(void);

/* Render markdown text for terminal display with ANSI color codes
 * @param markdown: Input markdown string
 * @return: Dynamically allocated string with rendered markdown (must be freed by caller)
 */
R_API char *r2ai_markdown(const char *markdown);

#endif /* R2_MARKDOWN_H */ 