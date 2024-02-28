from rich.console import Console
from rich.live import Live
from rich.panel import Panel
#from rich.markdown import Markdown
from rich.box import MINIMAL
import re

def Markdown(x):
  return x

class MessageBlock:

  def __init__(self):
    self.live = Live(auto_refresh=False, console=Console())
    self.live.start()
    self.content = ""

  def update_from_message(self, message):
    if type(message) != str and "content" in message:
      message = message["content"]
# msg = message if type(message) is str else message.get("content", "")
    message = re.sub(r"`+$", '', message)
    self.content = message
    self.refresh()

  def end(self):
    self.refresh(cursor=False)
    self.live.stop()

  def refresh(self, cursor=True):
    # De-stylize any code blocks in markdown to differentiate from our Code Blocks
    # WHY. this makes no sense, because codeblocks should be handled by the CodeBlocks class
    content = textify_markdown_code_blocks(self.content)
    
    if cursor:
      content += "█"
      
    markdown = Markdown(content.strip())
    panel = Panel(markdown, box=MINIMAL)
    self.live.update(panel)
    self.live.refresh()

def textify_markdown_code_blocks(text):
  return text
  """
  To distinguish CodeBlocks from markdown code, we simply turn all markdown code
  (like '```python...') into text code blocks ('```text') which makes the code black and white.
  """
  replacement = "```text"
  lines = text.split('\n')
  inside_code_block = False

  for i in range(len(lines)):
    # If the line matches ``` followed by optional language specifier
    if re.match(r'^```(\w*)$', lines[i].strip()):
      inside_code_block = not inside_code_block

      # If we just entered a code block, replace the marker
      if inside_code_block:
        lines[i] = replacement

  return '\n'.join(lines)
