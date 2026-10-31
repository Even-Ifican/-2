import argparse
import getpass
import gzip
import io
import re
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
                        "или путь к файлу тестового репозитория (с --test-mode)")
    p.add_argument("--test-mode", action="store_true",
                   help="режим работы с тестовым репозиторием")
    p.add_argument("--output", default="graph.png",
                   help="имя файла с изображением графа (по умолчанию graph.png)")
    p.add_argument("--ascii-tree", action="store_true",
                   help="вывод зависимостей в виде ASCII-дерева")
    p.add_argument("--max-depth", type=non_negative_int, default=3,
                   help="максимальная глубина анализа (по умолчанию 3)")
    p.add_argument("--filter", default="",
                   help="пакеты, в имени которых есть эта подстрока, "
                        "не учитываются")
    p.add_argument("--load-order", action="store_true",
                   help="вывести порядок загрузки зависимостей "
                        "(зависимости раньше зависимых пакетов)")
    return p


parser = build_parser()
config = {}


def format_config(cfg):
    return "\n".join(f"{key}: {value}" for key, value in cfg.items())



def load_apkindex_text(repo):
    if not repo:
        raise ValueError("не задан --repo")
    if not repo.startswith(("http://", "https://")):
        raise ValueError("--repo должен быть URL (http/https); "
                         "для файла используйте --test-mode")
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


def base_name(token):
    for i, ch in enumerate(token):
        if ch in "<>=~":
            return token[:i]
    return token


def load_apk_deps(repo):
    packages = parse_apkindex(load_apkindex_text(repo))
    by_name = {}
    for pkg in packages:
        by_name.setdefault(pkg["P"], pkg)

    provides = {}
    for pkg in packages:
        for token in pkg.get("p", "").split():
            provides.setdefault(base_name(token), pkg["P"])

    def resolve(token):
        name = base_name(token)
        if name in by_name:
            return name
        return provides.get(name, name)

    deps = {}
    for name, pkg in by_name.items():
        result = []
        for token in pkg.get("D", "").split():
            if token.startswith("!"):
                continue
            dep = resolve(token)
            if dep != name and dep not in result:
                result.append(dep)
        deps[name] = result
    return deps




NAME_RE = re.compile(r"^[A-Z]+$")


def load_test_deps(path):
    if not path:
        raise ValueError("не задан путь к файлу тестового репозитория (--repo)")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as e:
        raise ValueError(f"не удалось открыть файл {path}: {e}")

    deps = {}
    for num, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"строка {num}: ожидается формат 'A: B C'")
        name, _, rest = line.partition(":")
        name = name.strip()
        items = rest.replace(",", " ").split()
        for n in [name] + items:
            if not NAME_RE.match(n):
                raise ValueError(f"строка {num}: имя пакета '{n}' должно "
                                 f"состоять из заглавных латинских букв")
        deps.setdefault(name, [])
        for d in items:
            if d not in deps[name]:
                deps[name].append(d)
    return deps



def build_graph(root, deps_map, max_depth, substr):
    def expand(node):
        return [d for d in deps_map.get(node, [])
                if not (substr and substr in d)]

    order = [root]
    graph = {}
    cycles = []
    best = {root: 0}
    on_path = set()
    stack = []

    if max_depth > 0:
        graph[root] = expand(root)
        stack.append((root, 0, iter(graph[root])))
        on_path.add(root)

    while stack:
        node, depth, children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            on_path.discard(node)
            continue

        if child in on_path:
            path = [frame[0] for frame in stack]
            cycle = path[path.index(child):] + [child]
            if cycle not in cycles:
                cycles.append(cycle)
            continue

        d = depth + 1
        if child in best and best[child] <= d:
            continue
        if child not in best:
            order.append(child)
        best[child] = d

        if d < max_depth:
            graph[child] = expand(child)
            stack.append((child, d, iter(graph[child])))
            on_path.add(child)

    return order, graph, cycles


def ascii_tree(root, graph):
    lines = [root]
    stack = []

    def push_children(node, prefix, path):
        kids = graph.get(node, [])
        for i in range(len(kids) - 1, -1, -1):
            stack.append((kids[i], prefix, i == len(kids) - 1, path))

    push_children(root, "", (root,))
    while stack:
        node, prefix, last, path = stack.pop()
        connector = "└── " if last else "├── "
        if node in path:
            lines.append(f"{prefix}{connector}{node} (цикл)")
            continue
        lines.append(f"{prefix}{connector}{node}")
        push_children(node, prefix + ("    " if last else "│   "),
                      path + (node,))
    return lines

def load_order(root, graph):
    result = []
    visited = {root}
    stack = [(root, iter(graph.get(root, [])))]
    while stack:
        node, children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            result.append(node)
            continue
        if child in visited:
            continue
        visited.add(child)
        stack.append((child, iter(graph.get(child, []))))
    return result

def analyze(cfg):
    package, substr = cfg["package"], cfg["filter"]
    if substr and substr in package:
        raise ValueError(f"пакет '{package}' исключён фильтром '{substr}'")

    if cfg["test_mode"]:
        deps_map = load_test_deps(cfg["repo"])
        if package not in deps_map:
            raise ValueError(f"пакет '{package}' не найден "
                             f"в тестовом репозитории")
    else:
        deps_map = load_apk_deps(cfg["repo"])
        if package not in deps_map:
            raise ValueError(f"пакет '{package}' не найден в репозитории")

    order, graph, cycles = build_graph(package, deps_map,
                                       cfg["max_depth"], substr)

    out = [f"Граф зависимостей пакета {package} "
           f"(макс. глубина: {cfg['max_depth']}, "
           f"фильтр: {substr or 'нет'}):"]
    for node in order:
        if node not in graph:
            out.append(f"  {node} -> … (не раскрыт: предел глубины)")
        elif graph[node]:
            out.append(f"  {node} -> {', '.join(graph[node])}")
        else:
            out.append(f"  {node} -> (нет зависимостей)")
    out.append(f"Всего вершин: {len(order)}")

    if cycles:
        out.append("Циклические зависимости:")
        out += [f"  {' -> '.join(c)}" for c in cycles]
    else:
        out.append("Циклических зависимостей не найдено.")

    if cfg["load_order"]:
        out.append("")
        out.append("Порядок загрузки (зависимости раньше зависимых):")
        for i, name in enumerate(load_order(package, graph), 1):
            out.append(f"  {i}. {name}")

    if cfg["ascii_tree"]:
        out.append("")
        out.append("ASCII-дерево:")
        out += ascii_tree(package, graph)
    return "\n".join(out)



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

    try:
        result = analyze(config)
    except ValueError as e:
        write(f"Ошибка: {e}")
        return
    print(result)
    write(result)


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
    write("Пример: --package busybox "
          "--repo https://dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64")
    write("Тест:   --package A --repo test1.txt --test-mode")
    write("help — список опций, exit — выход")
show_prompt()
window.mainloop()