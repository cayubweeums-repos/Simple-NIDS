import curses
import sys
import time
from rich import print


class Menu:

    def __init__(self, stdscr, title, menu_items):
        self.stdscr = stdscr
        self.title = title
        self.menu_items = menu_items
        self.h, self.w = stdscr.getmaxyx()

    def get_selection(self):
        # Turn off blinking cursor
        curses.curs_set(0)

        indexed_row = 0

        # Initializes a color pair value for use later
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)

        self.stdscr.clear()
        self.stdscr.refresh()

        while True:
            self.draw_menu(self.stdscr, self.title, self.menu_items, indexed_row)
            self.stdscr.refresh()

            key = self.stdscr.getch()

            if key == curses.KEY_UP or key == 107 and indexed_row > 0:
                indexed_row -= 1
            elif key == curses.KEY_DOWN or key == 106 and indexed_row < len(self.menu_items) - 1:
                indexed_row += 1
            elif key == curses.KEY_ENTER or key in [10, 13]:
                self.stdscr.clear()
                self.stdscr.attron(curses.color_pair(1))
                self.stdscr.addstr(0, 0, f"You have selected {self.menu_items[indexed_row]}")
                self.stdscr.attroff(curses.color_pair(1))
                self.stdscr.refresh()
                time.sleep(2)
                self.stdscr.clear()
                curses.curs_set(1)
                self.stdscr.refresh()
                return indexed_row

    def draw_menu(self, stdscr, title, menu_items, indexed_row):
        stdscr.clear()

        # Draw the title above the options
        stdscr.attron(curses.color_pair(1))
        stdscr.addstr(self.h // 6, self.w // 2 - len(title) // 2, title)
        stdscr.attroff(curses.color_pair(1))

        # Set up each item on its own row based on terminal height and width
        for index, item in enumerate(menu_items):
            x = self.w // 2 - len(item) // 2
            y = self.h // 2 - len(menu_items) + index
            if index == indexed_row:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(y, x, item)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(y, x, item)

    def get_input(self):
        # Initializes a color pair value for use later
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_GREEN)

        self.stdscr.clear()

        # Draw the title above the options
        self.stdscr.attron(curses.color_pair(1))
        self.stdscr.addstr(self.h // 6, self.w // 2 - len(self.title) // 2, self.title)
        self.stdscr.attroff(curses.color_pair(1))

        # TODO Working on having and arrow '> ' and then a blinking cursor with echoed input from the user
        x = self.w // 2
        y = self.h // 2
        self.stdscr.addstr(y, x - 2, '> ')
        curses.echo()
        user_input = self.stdscr.getstr(y, x, 20)
        return user_input

