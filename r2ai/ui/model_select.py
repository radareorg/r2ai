from textual.app import ComposeResult
from textual.widgets import Input, OptionList
from textual.widget import Widget
from textual.widgets.option_list import Option
from textual.containers import Container
from textual.message import Message
from textual.binding import Binding
from textual.screen import ModalScreen, SystemModalScreen
from textual import log
# from ..models import models
# from ..repl import set_model, r2ai_singleton
# ai = r2ai_singleton()

# MODELS = models().split("\n")
from litellm import models_by_provider
MODELS = []
for provider in models_by_provider:
    for model in models_by_provider[provider]:
        MODELS.append(f"{provider}/{model}")
class ModalInput(Input):
    BINDINGS = [
        Binding("down", "cursor_down", "Move down"),
    ]


class ModelSelect(SystemModalScreen):
    BINDINGS = [
        Binding("up", "cursor_up", "Move up"),
        Binding("down", "cursor_down", "Move down"),
        Binding("enter", "select", "Select model"),
        Binding("escape", "app.pop_screen", "Close"),
    ]

    class ModelSelected(Message):
        """Event emitted when a model is selected."""
        def __init__(self, model: str) -> None:
            self.model = model
            super().__init__()

    def compose(self) -> ComposeResult:
        self.input = ModalInput(placeholder="Type to filter...")
        self.option_list = OptionList()
        with Container():
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
        self.input.focus()
    
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
        if self.option_list.has_focus:
            self.option_list.action_cursor_down()
        else:
            self.option_list.focus()

    def on_option_list_option_selected(self, index) -> None:
        selected_index = index.option_index
        if 0 <= selected_index < len(self.filtered_options):
            selected_option = self.filtered_options[selected_index]
            if not selected_option.disabled:
                self.dismiss(selected_option.id)
