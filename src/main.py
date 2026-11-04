import argparse
import getpass
import gzip
import io
import os
import re
import shlex
import socket
import subprocess
import sys
import tarfile
import tkinter as tk
import urllib.error
import urllib.request

HTTP_TIMEOUT = 30
DEFAULT_DEPTH = 3
APKINDEX_KEY_LEN = 1
APKINDEX_NAME = "APKINDEX.tar.gz"
VERSION_CHARS = "<>=~"
WINDOW_SIZE = "800x800"
NAME_RE = re.compile(r"^[A-Z]+$")


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
                        "https://dl-cdn.alpinelinux.org/alpine/v3.20/"
                        "main/x86_64) или путь к файлу тестового "
                        "репозитория (с --test-mode)")
    p.add_argument("--test-mode", action="store_true",
                   help="режим работы с тестовым репозиторием")
    p.add_argument("--output", default="graph.png",
                   help="имя файла с изображением графа "
                        "(по умолчанию graph.png)")
    p.add_argument("--ascii-tree", action="store_true",
                   help="вывод зависимостей в виде ASCII-дерева")
    p.add_argument("--max-depth", type=non_negative_int,
                   default=DEFAULT_DEPTH,
                   help="максимальная глубина анализа "
                        f"(по умолчанию {DEFAULT_DEPTH})")
    p.add_argument("--filter", default="",
                   help="пакеты, в имени которых есть эта подстрока, "
                        "не учитываются")
    p.add_argument("--load-order", action="store_true",
                   help="вывести порядок загрузки зависимостей "
                        "(зависимости раньше зависимых пакетов)")
    return p


parser = build_parser()


def format_config(cfg):
    return "\n".join(f"{key}: {value}" for key, value in cfg.items())


def download_apkindex(repo):
    if not repo:
        raise ValueError("не задан --repo")
    if not repo.startswith(("http://", "https://")):
        raise ValueError("--repo должен быть URL (http/https); "
                         "для файла используйте --test-mode")
    url = repo.rstrip("/")
    if not url.endswith(APKINDEX_NAME):
        url += "/" + APKINDEX_NAME
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} при загрузке {url}")
    except urllib.error.URLError as e:
        raise ValueError(f"не удалось загрузить {url}: {e.reason}")


def extract_apkindex(data):
    try:
        raw = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            member = next((m for m in tar.getmembers()
                           if m.name == "APKINDEX"), None)
            if member is None:
                raise ValueError("в архиве нет файла APKINDEX")
            content = tar.extractfile(member).read()
    except (OSError, tarfile.TarError, EOFError) as e:
        raise ValueError(f"не удалось распаковать APKINDEX: {e}")
    return content.decode("utf-8", errors="replace")


def load_apkindex_text(repo):
    return extract_apkindex(download_apkindex(repo))


def parse_apkindex(text):
    packages = []
    for block in text.split("\n\n"):
        entry = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            if sep and value and len(key) == APKINDEX_KEY_LEN:
                entry[key] = value
        if "P" in entry:
            packages.append(entry)
    return packages


def base_name(token):
    for i, ch in enumerate(token):
        if ch in VERSION_CHARS:
            return token[:i]
    return token


def build_provides(packages):
    provides = {}
    for pkg in packages:
        for token in pkg.get("p", "").split():
            provides.setdefault(base_name(token), pkg["P"])
    return provides


def resolve_dep(token, by_name, provides):
    name = base_name(token)
    if name in by_name:
        return name
    return provides.get(name, name)


def package_deps(name, pkg, by_name, provides):
    result = []
    for token in pkg.get("D", "").split():
        if token.startswith("!"):
            continue
        dep = resolve_dep(token, by_name, provides)
        if dep != name and dep not in result:
            result.append(dep)
    return result


def load_apk_deps(repo):
    packages = parse_apkindex(load_apkindex_text(repo))
    by_name = {}
    for pkg in packages:
        by_name.setdefault(pkg["P"], pkg)
    provides = build_provides(packages)
    return {name: package_deps(name, pkg, by_name, provides)
            for name, pkg in by_name.items()}


def parse_test_line(num, line):
    if ":" not in line:
        raise ValueError(f"строка {num}: ожидается формат 'A: B C'")
    name, _, rest = line.partition(":")
    name = name.strip()
    items = rest.replace(",", " ").split()
    for n in [name] + items:
        if not NAME_RE.match(n):
            raise ValueError(f"строка {num}: имя пакета '{n}' должно "
                             f"состоять из заглавных латинских букв")
    return name, items


def load_test_deps(path):
    if not path:
        raise ValueError("не задан путь к файлу тестового "
                         "репозитория (--repo)")
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
        name, items = parse_test_line(num, line)
        current = deps.setdefault(name, [])
        current.extend(d for d in items if d not in current)
    return deps


def expand_deps(node, deps_map, substr):
    return [d for d in deps_map.get(node, [])
            if not (substr and substr in d)]


def register_cycle(cycles, stack, child):
    path = [frame[0] for frame in stack]
    cycle = path[path.index(child):] + [child]
    if cycle not in cycles:
        cycles.append(cycle)


def build_graph(root, deps_map, max_depth, substr):
    order = [root]
    graph = {}
    cycles = []
    best = {root: 0}
    on_path = set()
    stack = []

    def push(node, depth):
        graph[node] = expand_deps(node, deps_map, substr)
        stack.append((node, depth, iter(graph[node])))
        on_path.add(node)

    if max_depth > 0:
        push(root, 0)
    while stack:
        node, depth, children = stack[-1]
        child = next(children, None)
        if child is None:
            stack.pop()
            on_path.discard(node)
            continue
        if child in on_path:
            register_cycle(cycles, stack, child)
            continue
        d = depth + 1
        if child in best and best[child] <= d:
            continue
        if child not in best:
            order.append(child)
        best[child] = d
        if d < max_depth:
            push(child, d)
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


def dot_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_dot(root, order, graph, cycles):
    cycle_edges = set()
    for c in cycles:
        cycle_edges.update(zip(c, c[1:]))

    lines = [f"digraph {dot_quote(root)} {{",
             "  rankdir=LR;",
             '  node [shape=box, fontname="Arial"];',
             f"  {dot_quote(root)} [style=filled, fillcolor=lightblue];"]
    for node in order:
        if node != root and node not in graph:
            lines.append(f"  {dot_quote(node)} [style=dashed];")
    for node, deps in graph.items():
        for dep in deps:
            attr = " [color=red]" if (node, dep) in cycle_edges else ""
            lines.append(f"  {dot_quote(node)} -> {dot_quote(dep)}{attr};")
    lines.append("}")
    return "\n".join(lines)


def save_graph(dot_text, output):
    folder = os.path.dirname(output)
    if folder:
        os.makedirs(folder, exist_ok=True)
    dot_path = os.path.splitext(output)[0] + ".dot"
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write(dot_text)
    try:
        subprocess.run(["dot", "-Tpng", "-o", output],
                       input=dot_text.encode("utf-8"),
                       check=True, capture_output=True)
    except FileNotFoundError:
        return (f"Graphviz не найден в PATH: PNG не создан, "
                f"описание графа сохранено в {dot_path}")
    except subprocess.CalledProcessError as e:
        return f"Ошибка dot: {e.stderr.decode('utf-8', errors='replace')}"
    return f"Изображение графа сохранено: {output} (описание: {dot_path})"


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


def load_deps_map(cfg):
    package = cfg["package"]
    if cfg["test_mode"]:
        deps_map = load_test_deps(cfg["repo"])
        where = "в тестовом репозитории"
    else:
        deps_map = load_apk_deps(cfg["repo"])
        where = "в репозитории"
    if package not in deps_map:
        raise ValueError(f"пакет '{package}' не найден {where}")
    return deps_map


def graph_report(cfg, order, graph):
    out = [f"Граф зависимостей пакета {cfg['package']} "
           f"(макс. глубина: {cfg['max_depth']}, "
           f"фильтр: {cfg['filter'] or 'нет'}):"]
    for node in order:
        if node not in graph:
            out.append(f"  {node} -> … (не раскрыт: предел глубины)")
        elif graph[node]:
            out.append(f"  {node} -> {', '.join(graph[node])}")
        else:
            out.append(f"  {node} -> (нет зависимостей)")
    out.append(f"Всего вершин: {len(order)}")
    return out


def cycles_report(cycles):
    if not cycles:
        return ["Циклических зависимостей не найдено."]
    out = ["Циклические зависимости:"]
    out += [f"  {' -> '.join(c)}" for c in cycles]
    return out


def load_order_report(package, graph):
    out = ["", "Порядок загрузки (зависимости раньше зависимых):"]
    for i, name in enumerate(load_order(package, graph), 1):
        out.append(f"  {i}. {name}")
    return out


def tree_report(cfg, order, graph, cycles):
    package = cfg["package"]
    dot_text = to_dot(package, order, graph, cycles)
    out = ["", "ASCII-дерево:"]
    out += ascii_tree(package, graph)
    out += ["", "Описание графа (Graphviz):", dot_text, ""]
    out.append(save_graph(dot_text, cfg["output"]))
    return out


def analyze(cfg):
    package, substr = cfg["package"], cfg["filter"]
    if substr and substr in package:
        raise ValueError(f"пакет '{package}' исключён фильтром '{substr}'")

    deps_map = load_deps_map(cfg)
    order, graph, cycles = build_graph(package, deps_map,
                                       cfg["max_depth"], substr)
    out = graph_report(cfg, order, graph) + cycles_report(cycles)
    if cfg["load_order"]:
        out += load_order_report(package, graph)
    if cfg["ascii_tree"]:
        out += tree_report(cfg, order, graph, cycles)
    return "\n".join(out)


class ConsoleApp:

    def __init__(self):
        self.config = {}
        username = getpass.getuser()
        hostname = socket.gethostname()
        self.prompt = f"{username}@{hostname}:~$ "

        self.window = tk.Tk()
        self.window.geometry(WINDOW_SIZE)
        self.window.title(f"{username}@{hostname}")
        self.console = tk.Text(self.window, bg="black", fg="white",
                               insertbackground="white",
                               font=("Consolas", 12), wrap="word")
        self.console.pack(fill="both", expand=True)
        self.bind_keys()

    def bind_keys(self):
        self.console.bind("<Return>", self.on_enter)
        self.console.bind("<KeyPress>", self.on_key)
        self.console.bind("<BackSpace>", self.on_backspace)
        self.console.bind("<Left>", self.on_backspace)
        self.console.bind("<Home>", self.on_home)

    def write(self, text=""):
        self.console.insert("end", text + "\n")
        self.console.see("end")

    def show_prompt(self):
        self.console.insert("end", self.prompt)
        self.console.mark_set("input_start", "end-1c")
        self.console.mark_gravity("input_start", "left")
        self.console.see("end")
        self.console.focus_set()

    def handle(self, args):
        if args and args[0] in ("-h", "--help", "help"):
            self.write(parser.format_help())
            return
        if args and args[0] in ("exit", "quit"):
            self.window.destroy()
            return
        try:
            self.config = vars(parser.parse_args(args))
        except ValueError as e:
            self.write(f"Ошибка: {e}")
            return
        text = format_config(self.config)
        print(text)
        self.write(text)
        self.write("")
        self.run_analysis()

    def run_analysis(self):
        try:
            result = analyze(self.config)
        except ValueError as e:
            self.write(f"Ошибка: {e}")
            return
        print(result)
        self.write(result)

    def on_enter(self, event):
        line = self.console.get("input_start", "end-1c")
        self.console.insert("end", "\n")
        try:
            args = shlex.split(line)
        except ValueError as e:
            self.write(f"Ошибка: {e}")
        else:
            if args:
                self.handle(args)
        if self.window.winfo_exists():
            self.show_prompt()
        return "break"

    def on_key(self, event):
        if self.console.compare("insert", "<", "input_start"):
            self.console.mark_set("insert", "end")

    def on_backspace(self, event):
        if self.console.compare("insert", "<=", "input_start"):
            return "break"

    def on_home(self, event):
        self.console.mark_set("insert", "input_start")
        return "break"

    def run(self, argv):
        if argv:
            self.handle(argv)
        else:
            self.write("Пример: --package busybox --repo https://"
                       "dl-cdn.alpinelinux.org/alpine/v3.20/main/x86_64")
            self.write("Тест:   --package A --repo test1.txt --test-mode")
            self.write("help — список опций, exit — выход")
        self.show_prompt()
        self.window.mainloop()


def main():
    """Точка входа."""
    ConsoleApp().run(sys.argv[1:])


if __name__ == "__main__":
    main()