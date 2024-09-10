from textual.app import ComposeResult
from textual.widgets import Input, OptionList
from textual.widget import Widget
from textual.widgets.option_list import Option
from textual.message import Message
from textual.binding import Binding
from textual import log
# from ..models import models
# from ..repl import set_model, r2ai_singleton
# ai = r2ai_singleton()

# MODELS = models().split("\n")
from litellm import model_list
from .db import get_env, set_env
MODELS = model_list

class ModelSelect(Widget):
    # BINDINGS = [
    #     Binding("up", "cursor_up", "Move up"),
    #     Binding("down", "cursor_down", "Move down"),
    #     Binding("enter", "select", "Select model"),
    # ]

    class ModelSelected(Message):
        """Event emitted when a model is selected."""
        def __init__(self, model: str) -> None:
            self.model = model
            super().__init__()

    def compose(self) -> ComposeResult:
        self.input = Input(placeholder="Type to filter...")
        self.option_list = OptionList()
        yield self.input
        yield self.option_list

    def on_mount(self) -> None:
        self.options = []
        for t in MODELS:
            if t.startswith("-m "):
                self.options.append(Option(t[3:], id=t[3:]))
            elif len(t) > 0:
                self.options.append(Option(t, id=t))
        self.option_list.add_options(self.options)
        self.filtered_options = self.options.copy()
        
        self.option_list.focus()
    
    def update_options(self, options):
        self.option_list.clear_options()
        self.option_list.add_options(options)
        self.filtered_options = options
    
    def on_input_changed(self, event: Input.Changed) -> None:
        filter_text = event.value
        filtered_options = [option for option in self.options if filter_text.lower() in option.id.lower()]
        self.update_options(filtered_options)

    def action_cursor_up(self) -> None:
        self.option_list.action_cursor_up()

    def action_cursor_down(self) -> None:
        self.option_list.action_cursor_down()

    def on_option_list_option_selected(self, index) -> None:
        selected_index = index.option_index
        if 0 <= selected_index < len(self.filtered_options):
            selected_option = self.filtered_options[selected_index]
            if not selected_option.disabled:
                set_env("model", selected_option.id)
                self.post_message(self.ModelSelected(selected_option.id))
