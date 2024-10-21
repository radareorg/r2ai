from textual.app import App, ComposeResult, SystemCommand
from textual.containers import ScrollableContainer, Container, Horizontal, VerticalScroll, Grid, Vertical  # Add Vertical to imports
from textual.widgets import Header, Footer, Input, Button, Static, DirectoryTree, Label, Tree, Markdown
from textual.command import CommandPalette, Command, Provider, Hits, Hit
from textual.screen import Screen, ModalScreen, SystemModalScreen
from textual.message import Message
from textual.reactive import reactive
from .model_select import ModelSelect
from r2ai.pipe import open_r2, get_filename, r2
from typing import Iterable
import os
from pathlib import Path 
from textual import work
from textual.widget import Widget
from textual.css.query import NoMatches
from textual import log
from litellm import validate_environment
from markdown_it import MarkdownIt
# from ..repl import set_model, r2ai_singleton
# ai = r2ai_singleton()
from .chat import chat
import asyncio
import json

class ModelConfigDialog(SystemModalScreen):
    def __init__(self, keys: list[str]) -> None:
        super().__init__()
        self.keys = keys

    def compose(self) -> ComposeResult:
        for key in self.keys:
            yield Input(placeholder=key, id=f"{key}-input")
        yield Button("Save", variant="primary", id="save-button")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-button":
            for key in self.keys:
                os.environ[key] = self.query_one(f"#{key}-input", Input).value
            self.dismiss()
class ChatMessage(Widget):
    markdown: reactive[str] = reactive("")
    sender = "User"
    is_done = reactive(False, layout=True, recompose=True)

    def __init__(self, id: str, sender: str, content: str, is_done: bool = False, **kwargs) -> None:
        super().__init__(id=id, classes='chat-message-container', **kwargs)
        # self.markdown = f"*{sender}*: {content}"
        self.markdown = content
        self.sender = sender
        self.is_done = is_done
    async def watch_markdown(self, markdown: str) -> None:
        try:
            mkd = self.query_exactly_one(".text1")
            text = self.markdown
            if hasattr(mkd, 'update') and callable(mkd.update):
                update_method = mkd.update
                if asyncio.iscoroutinefunction(update_method):
                    await update_method(text)
                else:
                    update_method(text)
        except NoMatches:
            pass

    def add_text(self, markdown: str) -> None:
        self.markdown += markdown

    def compose(self) -> ComposeResult:

        if self.sender == "User":
            yield Static(f"[bold green]{self.sender}", classes='label_sender', markup=True)
            yield Static(self.markdown, classes='text1', markup=True)
        elif self.sender == 'AI':
            yield Static(f"[bold magenta]{self.sender}", markup=True)
            if self.is_done:
                yield Markdown(self.markdown, classes='text1', parser_factory=lambda: MarkdownIt('gfm-like'))
            else:
                yield Static(self.markdown, classes='text1', markup=True)
        elif self.sender == 'Tool Call':
            yield Static(f"[bold blue]{self.sender}", markup=True)
            yield Static(self.markdown, classes='text1', markup=True)
        elif self.sender == 'Tool Response':
            yield Static(f"[bold blue]{self.sender}", markup=True)
            yield VerticalScroll(Static(self.markdown, classes='text1', markup=True), classes='tool_response_container')
        
        
        
            

class R2AIApp(App):
    CSS_PATH = "app.tcss"
    BINDINGS = [
        ("ctrl+p", "show_command_palette", "Command Palette"),
        ("ctrl+m", "select_model", "Select Model"),
        ("ctrl+o", "load_binary", "Load Binary")
    ]
    TITLE = "r2ai"
    SUB_TITLE = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__()
        if 'ai' in kwargs:
            self.ai = kwargs['ai']
        else:
            class FakeAI:
                model = 'gpt-4o'
                messages = []
            self.ai = FakeAI()
        self.update_sub_title(get_filename())

    def update_sub_title(self, binary: str = None) -> str:
        sub_title = None
        model = self.ai.model
        if binary and model:
            binary = Path(binary).name
            sub_title = f"{model} | {binary}"
        elif binary:
            sub_title = binary
        else:
            sub_title = model
        self.sub_title = sub_title

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            VerticalScroll(

                    id="chat-container",
            ),
            ScrollableContainer(
                    Horizontal(
                        Input(placeholder="Type your message here...", id="chat-input"),
                        Button("Send", variant="primary", id="send-button"),
                        id="input-container",
                    ),
                    id="input-area",
            ),
            id="content",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.install_screen(CommandPalette(), name="command_palette")
        self.query_one("#chat-input", Input).focus()
        # self.install_screen(BinarySelectDialog(), name="binary_select_dialog")

    def action_show_command_palette(self) -> None:
        self.push_screen("command_palette")
    
    
    async def select_model(self) -> None:
        model = await self.push_screen_wait(ModelSelect())
        if model:
            await self.validate_model()
            self.ai.model = model
            self.notify(f"Selected model: {self.ai.model}")
        self.update_sub_title()

    @work
    async def action_select_model(self) -> None:
        await self.select_model()

    @work
    async def action_load_binary(self) -> None:
        binary = await self.push_screen_wait(BinarySelectDialog())
        if binary:
            self.notify(f"Selected binary: {binary}")
        self.update_sub_title(binary)
        
    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("Models", "Select Model", self.action_select_model)
        yield SystemCommand("Load Binary", "Load Binary", self.action_load_binary)  # Add this command

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send-button":
            self.send_message()

    @work
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            await self.send_message()

    def on_message(self, type: str, message: any) -> None:
        if type == 'message':
            existing = None
            try:
                existing = self.query_one(f"#{message['id']}")
                if message["content"] is not None:
                    existing.add_text(message["content"])
                if message['done']:
                    existing.is_done = True
                self.scroll_to_bottom()
            except NoMatches:
                existing = self.add_message(message["id"], "AI", message["content"])
        elif type == 'tool_call':
            self.add_message(message["id"], "Tool Call", f"{message['function']['name']} > {message['function']['arguments']['command']}")
        elif type == 'tool_response':
            self.add_message(message["id"], "Tool Response", message['content'])
        

    async def send_message(self) -> None:
        input_widget = self.query_one("#chat-input", Input)
        message = input_widget.value.strip()
        if message:
            self.add_message(None, "User", message)
            input_widget.value = ""
            try:
                await self.validate_model()
                await chat(self.ai, message, self.on_message)
            except Exception as e:
                self.notify(str(e), severity="error")

    async def validate_model(self) -> None:
        model = self.ai.model
        if not model:
            await self.select_model()
        model = self.ai.model
        keys = validate_environment(model)
        if keys['keys_in_environment'] is False:
            await self.push_screen_wait(ModelConfigDialog(keys['missing_keys']))
            
        return True

    def add_message(self, id: str, sender: str, content: str) -> None:
        chat_container = self.query_one("#chat-container", VerticalScroll)
        try:
            msg = ChatMessage(id, sender, content)
            chat_container.mount(msg)
            return msg
        except Exception as e:
            pass
        finally:
            self.scroll_to_bottom()
        

    def scroll_to_bottom(self) -> None:
        chat_scroll = self.query_one("#chat-container", VerticalScroll)
        chat_scroll.scroll_end(animate=False)
class Message(Widget):
    def __init__(self, message: str) -> None:
        super().__init__()
        self.content = f'[bold]{message.role}[/] {message.content}'

    def render(self) -> str:
        return Markdown(self.content)

class Messages(Container):
    def __init__(self, messages) -> None:
        self.messages = messages
    def compose(self) -> ComposeResult:
        for message in self.messages:
            yield Message(message)

class FilteredDirectoryTree(DirectoryTree):
    input_path: reactive[Path] = reactive(Path.home())

    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        ps = [path for path in paths if str(path).startswith(str(self.input_path))]
        return ps

class BinarySelectDialog(SystemModalScreen):
    BINDINGS = [
        ("up", "cursor_up", "Move cursor up"),
        ("down", "cursor_down", "Move cursor down"),
        ("enter", "select_cursor", "Select item"),
        ("escape", "app.pop_screen", "Close"),
        ("backspace", "go_up", "Go up one level"),  # Add this binding
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Input(placeholder="Enter path here...", id="path-input")
            yield FilteredDirectoryTree(Path.home(), id="file-browser")

    def on_mount(self) -> None:
        self.path_input = self.query_one("#path-input", Input)
        self.file_browser = self.query_one("#file-browser", DirectoryTree)
        self.path_input.value = str(get_filename() or Path.home())
        self.path_input.focus()
        self.watch(self.path_input, "value", self.update_tree)

    @work(thread=True)
    def update_tree(self) -> None:
        path = Path(self.path_input.value)
        
        if path.exists():
            self.file_browser.path = str(path)
        elif path.parent.exists():
            self.file_browser.path = str(path.parent)
        self.file_browser.input_path = str(path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "up-button":
            self.go_up()

    def action_go_up(self) -> None:
        current_path = Path(self.file_browser.path)
        parent_path = current_path.parent
        if parent_path != current_path:
            self.file_browser.path = str(parent_path)
            self.path_input.value = str(parent_path)

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:  
        self.path_input.value = str(event.path)
        self.open_and_analyze_binary(str(event.path))
        self.dismiss(str(event.path))
    
    @work(thread=True)
    def open_and_analyze_binary(self, path: str) -> None:
        global r2
        r2 = open_r2(path)
        res = json.loads(r2.cmd('{ "cmd":"aaa" }'))
        if 'error' in res and res['error'] is True:
            self.notify(res['error'], severity="error")

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.path_input.value = str(event.path)

    def action_cursor_up(self) -> None:
        self.file_browser.action_cursor_up()

    def action_cursor_down(self) -> None:
        self.file_browser.focus()
        self.file_browser.action_cursor_down()

    def action_select(self) -> None:
        node = self.file_browser.cursor_node
        if hasattr(node.data, 'is_file') and node.data.is_file:
            self.open_and_analyze_binary(str(node.data.path))
            self.dismiss(str(node.data.path))

# app = R2AIApp()
# app.run()
