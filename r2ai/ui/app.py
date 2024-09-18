from textual.app import App, ComposeResult, SystemCommand
from textual.containers import ScrollableContainer, Container, Horizontal, VerticalScroll, Grid, Vertical  # Add Vertical to imports
from textual.widgets import Header, Footer, Input, Button, Static, DirectoryTree, Label, Tree, Markdown
from textual.command import CommandPalette, Command, Provider, Hits, Hit
from textual.screen import Screen
from textual.message import Message
from textual.reactive import reactive
from .model_select import ModelSelect
from r2ai.pipe import open_r2
from typing import Iterable
import os
from pathlib import Path 
from textual import work
from textual.widget import Widget
from textual.css.query import NoMatches

# from ..repl import set_model, r2ai_singleton
# ai = r2ai_singleton()
from .chat import chat, messages
import asyncio
from .db import get_env
r2 = None
class ModelSelectProvider(Provider):
    async def search(self, query: str) -> Hits:
        yield Hit("Select Model", "Select Model", self.action_select_model)


class ModelSelectDialog(Screen):
    def compose(self) -> ComposeResult:
        yield Grid(ModelSelect(), id="model-select-dialog")

    def on_model_select_model_selected(self, event: ModelSelect.ModelSelected) -> None:
        self.dismiss(event.model)


class ChatMessage(Markdown):
    markdown = ""
    def __init__(self, id: str, sender: str, content: str, ) -> None:
        self.markdown = f"*{sender}:* {content}"
        super().__init__(id=id, markdown=self.markdown)
    def add_text(self, markdown: str) -> None:
        self.markdown += markdown
        self.update(self.markdown)


class R2AIApp(App):
    CSS_PATH = "app.tcss"
    BINDINGS = [
        ("ctrl+p", "show_command_palette", "Command Palette"),
    ]
    TITLE = "r2ai"

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
        # self.install_screen(BinarySelectDialog(), name="binary_select_dialog")

    def action_show_command_palette(self) -> None:
        self.push_screen("command_palette")

    def action_select_model(self) -> None:
        model = self.push_screen(ModelSelectDialog())
        if model:
            self.notify(f"Selected model: {get_env('model')}")

    def action_load_binary(self) -> None:
        self.push_screen(BinarySelectDialog())
        
    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("Models", "Select Model", self.action_select_model)
        yield SystemCommand("Load Binary", "Load Binary", self.action_load_binary)  # Add this command

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "send-button":
            self.send_message()
    def on_model_select_model_selected(self, event: ModelSelect.ModelSelected) -> None:
        self.notify(f"Selected model: {event.model}")

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            await self.send_message()

    def on_message(self, type: str, message: any) -> None:
        if type == 'message':
            existing = None
            try:
                existing = self.query_one(f"#{message['id']}")
            except NoMatches:
                existing = self.add_message(message["id"], "AI", "")
            print(existing)
            existing.add_text(message["content"])
        elif type == 'tool_call':
            self.add_message(message["id"], "AI", f"*Tool Call:* {message['function']['name']}")
        elif type == 'tool_response':
            self.add_message(message["id"], "AI", f"*Tool Response:* {message['content']}")

    async def send_message(self) -> None:
        input_widget = self.query_one("#chat-input", Input)
        message = input_widget.value.strip()
        if message:
            self.add_message(None, "User", message)
            input_widget.value = ""
            await chat(message, self.on_message)

    def add_message(self, id: str, sender: str, content: str) -> None:
        chat_container = self.query_one("#chat-container", VerticalScroll)
        msg = ChatMessage(id, sender, content)
        chat_container.mount(msg)
        self.scroll_to_bottom()
        return msg

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


class BinarySelectDialog(Screen):
    BINDINGS = [
        ("up", "cursor_up", "Move cursor up"),
        ("down", "cursor_down", "Move cursor down"),
        ("enter", "select_cursor", "Select item"),
        ("escape", "app.pop_screen", "Close"),
        ("backspace", "go_up", "Go up one level"),  # Add this binding
    ]

    def compose(self) -> ComposeResult:
        yield Grid(
            Vertical(
                Input(placeholder="Enter path here...", id="path-input"),
                DirectoryTree(Path.home(), id="file-browser"),
            ),
            id="binary-select-dialog"
        )

    def on_mount(self) -> None:
        self.path_input = self.query_one("#path-input", Input)
        self.file_browser = self.query_one("#file-browser", DirectoryTree)
        self.set_focus(self.file_browser)
        self.watch(self.path_input, "value", self.update_tree)

    @work(thread=True)
    def update_tree(self) -> None:
        path = Path(self.path_input.value)
        if path.exists():
            self.file_browser.path = str(path)
        elif path.parent.exists():
            self.file_browser.path = str(path.parent)

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
        r2.cmd("aaa")

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        self.path_input.value = str(event.path)

    def action_cursor_up(self) -> None:
        self.file_browser.action_cursor_up()

    def action_cursor_down(self) -> None:
        self.file_browser.action_cursor_down()

    def action_select(self) -> None:
        node = self.file_browser.cursor_node
        if hasattr(node.data, 'is_file') and node.data.is_file:
            self.open_and_analyze_binary(str(node.data.path))
            self.dismiss(str(node.data.path))

app = R2AIApp()
app.run()
