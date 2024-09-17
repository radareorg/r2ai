from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, Task
from rich.console import Console
from .web import server_running, server_in_background
from inspect import signature
from functools import wraps


def _support_total(sig, *args, **kwargs):
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return "__progress_cls" in bound.arguments and "__progress_task" in bound.arguments


def progress_bar(text, color=None, total=None, infinite=False):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            sig = signature(func)
            has_total = total is not None and _support_total(
                sig, *args, **kwargs)
            is_infinite = infinite or not has_total

#            if server_running() and not server_in_background():
            return func(*args, **kwargs)

            with Progress(SpinnerColumn(), *Progress.get_default_columns(), console=Console(no_color=not bool(color)), transient=False) as p:
                task_text = f"[{color}]{text}" if color else text
                task = p.add_task(
                    task_text, total=None if is_infinite else total)

                if has_total:
                    result = func(
                        *args,
                        **kwargs,
                        __progress_cls=p,
                        __progress_task=task)
                else:
                    result = func(*args, **kwargs)

            return result
        return wrapper
    return decorator

# For consistency with the above
class ProgressBar:
    def __init__(self, text, color=None, total=None, infinite=False) -> None:
        self.text = text
        self.color = color
        self.total = total
        self.infinite = infinite
        self.progress: Progress = None
        self.task: Task = None

    def __enter__(self):
        self.progress = Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            console=Console(
                no_color=not bool(
                    self.color)),
            transient=False)
        if self.color:
            self.task = self.progress.add_task(
                f"[{self.color}]{self.text}", total=None if self.infinite else self.total)
        else:
            self.task = self.progress.add_task(
                f"{self.text}", total=None if self.infinite else self.total)
        self.progress.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.progress:
            self.progress.stop()

# from .progress import ProgressBar, progress_bar
# progress_bar is used as an decorator
# @progress_bar(Title, color="yellow")
# def foo():
#    bar
#
#
# unlike in the class, the decorated functin can only use progressive progress only if
#   __progress_cls and __progress_task are used as positional arguments. else it defaults to infinite
# @progress_bar("Title", color="yellow", total=100)
# def foo(a,b, __progress_cls=None, __progress_task=None):
#   i = 1
#   while True:
        # progress_cls.update(p.task, advance=i)
        # i+=1
        # time.sleep(1)
#
#
# ProgressBar is made for consistency with the decorator
# import time
# with ProgressBar("Title", color="Yellow", total=50) as p:
#   i = 0
#   while True:
        # p.progress.update(p.task, advance=i)
        # i+=1
        # time.sleep(1)
