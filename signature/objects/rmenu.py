import os
import keyboard
from rich import pretty
from rich.console import Console
from rich.panel import Panel
from rich.highlighter import Highlighter
from rich.markdown import Markdown
from time import sleep
from rich.layout import Layout
from rich.live import Live

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text


class Rmenu:

    def __init__(self, prompt, menu_items):
        self.prompt = prompt
        self.menu_items = menu_items
        self.console = Console()
        self.layout = Layout(name='root')
        self.option_selected = False
        pretty.install()

    def get_selection(self):
        indexed_row = 0
        os.system('clear')

        # Split the 'screen' into the following sections
        self.layout.split(
            Layout(name='title', size=5),
            Layout(name='body', ratio=1),
            Layout(name='footer', size=3)
        )

        # Create title panel with menu prompt
        prompt_table = Table.grid(expand=True)
        prompt_table.add_column(justify="center", ratio=1)
        prompt_table.add_row(
            f'[b white on black]{self.prompt}',
        )

        # Create footer panel
        footer_table = Table.grid(expand=True)
        footer_table.add_column(justify="center", ratio=1)
        footer_table.add_row(
            '[b white on black]Use arrow keys or J and K to navigate the menu\nPress '
        )

        self.layout['title'].update(Panel(
            Align.center(Group(prompt_table), vertical='middle'),
            box=box.ROUNDED,
            border_style='white')
        )
        self.layout['body'].update(self.draw_menu(indexed_row))
        self.layout['footer'].update(Panel(
            Align.center(Group(footer_table)),
            box=box.ROUNDED,
            border_style='white')
        )

        with Live(self.layout, refresh_per_second=10, screen=True):
            while not self.option_selected:
                self.layout['body'].update(self.draw_menu(indexed_row))
                if keyboard.is_pressed('up') and indexed_row > 0 or keyboard.is_pressed('k') and indexed_row > 0:
                    indexed_row -= 1
                    sleep(0.3)
                elif keyboard.is_pressed('down') and indexed_row > 0 or keyboard.is_pressed('j') and indexed_row < len(self.menu_items) - 1:
                    indexed_row += 11
                    sleep(0.3)
                elif keyboard.is_pressed('enter'):
                    os.system('clear')
                    self.console.print(f'You selected {self.menu_items[indexed_row]}', style='bold black on green')
                    sleep(30)
                    return indexed_row


        #
        # self.console.print('\n\n\n')
        # self.console.print('This should be hightlighted and in the center', justify="center",
        #                    style="bold black on green")
        # self.console.print('This should not be highlighted and should be in the center', justify="center")
        # sleep(10)

    def draw_menu(self, indexed_row) -> Panel:
        body_table = Table.grid(padding=1)
        body_table.add_column(justify='center')

        for item in self.menu_items:
            if self.menu_items.index(item) == indexed_row:
                body_table.add_row(item, style='bold black on green')
            else:
                body_table.add_row(item, style='bold white on black')

        body_panel = Panel(
            Align.center(Group(body_table), vertical='middle'),
            box=box.ROUNDED,
            padding=(1, 2),
            border_style='green'
        )
        return body_panel
