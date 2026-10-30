import argparse
import getpass
import gzip
import io
import os
import shlex
import socket
import sys
import tarfile
import tkinter as tk
import urllib.error
import urllib.request


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
                   help="URL репозитория (например "
                        "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64) "
                        "или путь к файлу тестового репозитория")
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



def load_apkindex_text(repo, test_mode):
    if not repo:
        raise ValueError("не задан --repo")

    if test_mode or os.path.exists(repo):
        if not os.path.isfile(repo):
            raise ValueError(f"файл тестового репозитория не найден: {repo}")
        with open(repo, "rb") as f:
            data = f.read()
    else:
        if not repo.startswith(("http://", "https://")):
            raise ValueError("--repo должен быть URL (http/https) "
                             "или путём к файлу в тестовом режиме")
        url = repo.rstrip("/")
        if not url.endswith("APKINDEX.tar.gz"):
            url += "/APKINDEX.tar.gz"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = resp.read()
        except urllib.error.HTTPError as e:
            raise ValueError(f"HTTP {e.code} при загрузке {url}")
        except urllib.error.URLError as e:
            raise ValueError(f"не удалось загрузить {url}: {e.reason}")

    if data[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(data)
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
                member = next((m for m in tar.getmembers()
                               if m.name == "APKINDEX"), None)
                if member is None:
                    raise ValueError("в архиве нет файла APKINDEX")
                data = tar.extractfile(member).read()
        except (OSError, tarfile.TarError, EOFError) as e:
            raise ValueError(f"не удалось распаковать APKINDEX: {e}")

    return data.decode("utf-8", errors="replace")


def parse_apkindex(text):
    packages = []
    for block in text.split("\n\n"):
        entry = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                entry[line[0]] = line[2:]
        if "P" in entry:
            packages.append(entry)
    return packages


def find_package(packages, name):
    for pkg in packages:
        if pkg["P"] == name:
            return pkg
    for pkg in packages:
        for provided in pkg.get("p", "").split():
            if provided.split("=")[0] == name:
                return pkg
    return None


def get_direct_dependencies(package, repo, test_mode):
    packages = parse_apkindex(load_apkindex_text(repo, test_mode))
    pkg = find_package(packages, package)
    if pkg is None:
        raise ValueError(f"пакет '{package}' не найден в репозитории")
    return pkg, pkg.get("D", "").split()



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


    write("")
    write("Загрузка данных репозитория...")
    window.update_idletasks()
    try:
        pkg, deps = get_direct_dependencies(
            config["package"], config["repo"], config["test_mode"])
    except ValueError as e:
        write(f"Ошибка: {e}")
        return

    header = f"Прямые зависимости пакета {pkg['P']} {pkg.get('V', '')}:"
    lines = [header]
    if deps:
        lines += [f"  {i}. {d}" for i, d in enumerate(deps, 1)]
    else:
        lines.append("  (нет зависимостей)")
    out = "\n".join(lines)
    print(out)
    write(out)


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
    write("Введите опции, например: --package busybox "
          "--repo https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64")
    write("help — список опций, exit — выход")
show_prompt()
window.mainloop()