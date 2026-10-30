import argparse
import getpass
import shlex
import socket
import sys
import tkinter as tk



class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def non_negative_int(s):
    n = int(s)
    if n < 0:
        raise argparse.ArgumentTypeError("глубина не может быть отрицательной")
    return n


def build_parser():
    p = Parser(prog="main.py", add_help=False,
               description="Анализатор зависимостей пакета")
    p.add_argument("--package", required=True,
                   help="имя анализируемого пакета")
    p.add_argument("--repo", default="",
                   help="URL репозитория или путь к файлу тестового репозитория")
    p.add_argument("--test-mode", action="store_true",
                   help="режим работы с тестовым репозиторием")
    p.add_argument("--output", default="graph.png",
                   help="имя файла с изображением графа (по умолчанию graph.png)")
    p.add_argument("--ascii-tree", action="store_true",
                   help="вывод зависимостей в виде ASCII-дерева")
    p.add_argument("--max-depth", type=non_negative_int, default=3,
                   help="максимальная глубина анализа (по умолчанию 3)")
    p.add_argument("--filter", default="",
                   help="подстрока для фильтрации пакетов")
    return p


parser = build_parser()
config = {}


def format_config(cfg):
    return "\n".join(f"{key}: {value}" for key, value in cfg.items())



username = getpass.getuser()
hostname = socket.gethostname()
PROMPT = f"{username}@{hostname}:~$ "

window = tk.Tk()
window.geometry("800x800")
window.title(f"{username}@{hostname}")

console = tk.Text(window, bg="black", fg="white", insertbackground="white",
                  font=("Consolas", 12), wrap="word")
console.pack(fill="both", expand=True)


def write(text=""):
    console.insert("end", text + "\n")
    console.see("end")


def show_prompt():
    console.insert("end", PROMPT)
    console.mark_set("input_start", "end-1c")
    console.mark_gravity("input_start", "left")
    console.see("end")
    console.focus_set()


def handle(args):
    global config
    if args and args[0] in ("-h", "--help", "help"):
        write(parser.format_help())
        return
    if args and args[0] in ("exit", "quit"):
        window.destroy()
        return
    try:
        config = vars(parser.parse_args(args))
    except ValueError as e:
        write(f"Ошибка: {e}")
        return
    text = format_config(config)
    print(text)
    write(text)


def on_enter(event):
    line = console.get("input_start", "end-1c")
    console.insert("end", "\n")
    try:
        args = shlex.split(line)
    except ValueError as e:
        write(f"Ошибка: {e}")
    else:
        if args:
            handle(args)
    if window.winfo_exists():
        show_prompt()
    return "break"


def on_key(event):
    if console.compare("insert", "<", "input_start"):
        console.mark_set("insert", "end")


def on_backspace(event):
    if console.compare("insert", "<=", "input_start"):
        return "break"


def on_home(event):
    console.mark_set("insert", "input_start")
    return "break"


console.bind("<Return>", on_enter)
console.bind("<KeyPress>", on_key)
console.bind("<BackSpace>", on_backspace)
console.bind("<Left>", on_backspace)
console.bind("<Home>", on_home)


if len(sys.argv) > 1:
    handle(sys.argv[1:])
else:
    write("Введите опции, например: --package requests --max-depth 5")
    write("help — список опций, exit — выход")
show_prompt()
window.mainloop()