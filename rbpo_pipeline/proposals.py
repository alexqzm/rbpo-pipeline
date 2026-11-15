# -*- coding: utf-8 -*-
"""Предложения ИИ-агента по разметке: очередь, проверка предложений, контроль ветки агента.

От файла разметки (.rbpo/triage.yaml) зависит решение по выпуску, поэтому агент его не правит.
Агент пишет предложения в отдельный каталог (по умолчанию .rbpo/proposals/), которого конвейер не
читает; решение в файл разметки переносит человек. Модуль даёт три проверяемые опоры:

  queue   что в комплекте свидетельств ждёт решения (sca/triage.json, sast/triage.json);
  check   проверка файлов предложений по правилам ПП01–ПП11: формат, соответствие комплекту, запрет
          шаблонов и принятия риска, ссылки на код с дословной цитатой, срок пересмотра;
  guard   изменения ветки агента вне каталога предложений.

Файл предложений недоверенный: его написала модель, которая могла прочитать чужой текст (описание
уязвимости, комментарий в коде) и последовать записанной в нём инструкции. Поэтому формат строгий,
а каждая ссылка на код сверяется с файлом проекта. Проверка подтверждает форму предложения и то,
что процитированные строки существуют; верен ли вывод агента, решает человек.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import unicodedata
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from . import source, triage
from .config import SAST_LEVELS, SCA_LEVELS

SCHEMA = "rbpo-pipeline/triage-proposals/v1"
PROPOSALS_DIR = ".rbpo/proposals"
ALLOWED = tuple(f"{PROPOSALS_DIR}/*{ext}" for ext in (".yaml", ".yml", ".md", ".json"))

MAX_FILE_BYTES = 1 << 20      # файл предложений
MAX_SOURCE_BYTES = 2 << 20    # файл проекта, на который ссылается предложение
MAX_PROPOSALS = 500
MAX_REFS = 20
MAX_TEXT = 2000
MAX_QUOTE_LINES = 20
MIN_REASON = 30               # знаков в обосновании
MIN_QUOTE = 8                 # знаков в цитате без пробелов
MAX_DAYS = 180                # срок пересмотра снимающего решения

# Решения, которые может предложить агент. accepted (принятие риска) — только человек.
AGENT_VERDICTS = {"vulnerability": ("not_affected", "confirmed"), "sast": ("false_positive", "confirmed")}
CLEARING = ("not_affected", "false_positive")
RULES = {
    "ПП01": "формат файла предложений",
    "ПП02": "предложение не относится ни к одному элементу комплекта свидетельств",
    "ПП03": "шаблон вместо точного значения",
    "ПП04": "принятие риска (accepted) агент не предлагает",
    "ПП05": "обоснование слишком короткое",
    "ПП06": "снимающее решение без ссылки на код проекта",
    "ПП07": "ссылка на код не подтверждается",
    "ПП08": "срок пересмотра не задан или вне допустимого",
    "ПП09": "повторное предложение по тому же элементу",
    "ПП10": "версия пакета в предложении не та, что в комплекте свидетельств",
    "ПП11": "по элементу уже есть решение в файле разметки",
}
STATUS_RU = {"blocking": "блокирует", "below_threshold": "ниже порога", "confirmed": "подтверждено",
             "decided": "есть решение"}
NOTICE = ("Проверка подтверждает форму предложений и существование процитированных строк, "
          "а не правильность выводов. Решение принимает человек.")

_TOP_KEYS = {"schema", "meta", "proposals"}
_META_KEYS = {"agent", "model", "skill", "run", "created"}
_COMMON_KEYS = {"kind", "verdict", "reason", "until", "refs"}
_KIND_KEYS = {"vulnerability": ("id", "package", "version"), "sast": ("rule", "path", "line")}
_REF_KEYS = {"path", "line", "quote", "note"}
_ORDER = {"blocking": 0, "below_threshold": 1, "confirmed": 2, "decided": 3}
_RANK = {level: n for n, level in enumerate(SCA_LEVELS + SAST_LEVELS)}


class ProposalError(ValueError):
    """Ошибка входных данных: нет результатов анализа в комплекте, нет файла предложений."""


# ---------------------------------------------------------------- текст из недоверенного файла
def _hidden(text: str) -> bool:
    """Управляющие и невидимые символы: в отчёте человек и программа прочли бы разное."""
    return any(unicodedata.category(c) in ("Cc", "Cf") and c not in "\n\t" for c in text)


def clean(text) -> str:
    """Значение из файла предложений для вывода: одной строкой, без управляющих символов."""
    return "".join(" " if c in "\r\n\t" else ("�" if unicodedata.category(c) in ("Cc", "Cf") else c)
                   for c in str(text))


def _norm(text: str) -> str:
    return " ".join(text.split())


class _Loader(yaml.SafeLoader):
    """SafeLoader, который отвергает повторяющиеся ключи: PyYAML молча оставил бы последний."""


def _unique_mapping(loader: _Loader, node: yaml.MappingNode) -> dict:
    loader.flatten_mapping(node)
    keys = [repr(loader.construct_object(k, deep=True)) for k, _ in node.value]
    twice = sorted(k for k, n in Counter(keys).items() if n > 1)
    if twice:
        raise yaml.constructor.ConstructorError(None, None, f"повторяющийся ключ {twice[0]}", node.start_mark)
    return loader.construct_mapping(node, deep=True)


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


# ---------------------------------------------------------------- очередь разметки
def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def vuln_key(i: dict) -> str:
    return f"vulnerability:{i.get('id', '')}:{i.get('package', '')}@{i.get('version', '')}"


def sast_key(i: dict) -> str:
    return f"sast:{i.get('rule', '')}:{i.get('path', '')}:{i.get('line')}"


def _status(i: dict) -> str:
    if i.get("verdict") == "untriaged":
        return "blocking" if i.get("blocking") else "below_threshold"
    return "confirmed" if i.get("verdict") == "confirmed" else "decided"


def items(out: Path) -> Dict[str, Optional[dict]]:
    """Срабатывания и уязвимости комплекта свидетельств с ключом и состоянием разметки."""
    out = Path(out)
    res: Dict[str, Optional[dict]] = {"sca": None, "sast": None}
    for section, kind, key in (("sca", "vulnerability", vuln_key), ("sast", "sast", sast_key)):
        data = _load_json(out / section / "triage.json")
        if data is not None:
            res[section] = {"fail_on": data.get("fail_on", ""),
                            "items": [dict(i, kind=kind, key=key(i), status=_status(i))
                                      for i in data.get("items", [])]}
    return res


def _all_items(out: Path) -> List[dict]:
    data = items(out)
    if data["sca"] is None and data["sast"] is None:
        raise ProposalError(f"в комплекте {out} нет результатов анализа (sca/triage.json, sast/triage.json): "
                            "сначала выполните шаги sca и sast")
    return [i for section in ("sca", "sast") for i in (data[section] or {}).get("items", [])]


def _sort_key(i: dict):
    return (_ORDER[i["status"]], i["kind"] != "vulnerability", _RANK.get(i.get("severity") or i.get("level"), 99),
            i["key"])


def queue(out: Path) -> dict:
    """Что ждёт решения: блокирующие элементы, элементы ниже порога и подтверждённые к исправлению."""
    out = Path(out)
    data = items(out)
    every = _all_items(out)
    counts = Counter(i["status"] for i in every)
    expired = sum(1 for i in every if i["status"] != "decided" and i.get("expired_decisions"))
    sec = _load_json(out / "secrets" / "summary.json")
    integrity = _load_json(out / "source" / "integrity.json") or {}
    return {
        "schema": "rbpo-pipeline/triage-queue/v1",
        "commit": integrity.get("head", ""),
        "fail_on": {s: (data[s] or {}).get("fail_on") for s in ("sca", "sast")},
        "summary": {k: counts.get(k, 0) for k in ("blocking", "below_threshold", "confirmed", "decided")}
        | {"expired": expired},
        "secrets": None if sec is None else {"ran": bool(sec.get("ran")), "findings": sec.get("findings", 0)},
        "items": sorted((i for i in every if i["status"] != "decided"), key=_sort_key),
    }


def _item_line(i: dict) -> str:
    if i["kind"] == "vulnerability":
        fixed = f"исправлено в {', '.join(i.get('fixed_in') or [])}" if i.get("fixed_in") else "исправления нет"
        what = f"{i.get('severity', ''):<9} {i['id']}  {i['package']} {i['version']}, {fixed}"
    else:
        what = f"{i.get('level', ''):<9} {i['rule']}  {i['path']}:{i['line']}"
    tail = "; прежнее решение истекло" if i.get("expired_decisions") else ""
    return clean(f"  {STATUS_RU[i['status']]:<12} {what}{tail}")


def render_queue(q: dict) -> str:
    s = q["summary"]
    L = [f"Очередь разметки{' (коммит ' + q['commit'][:12] + ')' if q['commit'] else ''}: блокирует выпуск "
         f"{s['blocking']}, ниже порога {s['below_threshold']}, подтверждено к исправлению {s['confirmed']}, "
         f"с решением {s['decided']}, истёкших решений {s['expired']}",
         f"Пороги: уязвимости — {q['fail_on']['sca'] or 'нет результатов'}, "
         f"статический анализ — {q['fail_on']['sast'] or 'нет результатов'}", ""]
    L += [_item_line(i) for i in q["items"]] or ["  элементов без решения нет"]
    if q["secrets"] and q["secrets"]["findings"]:
        L += ["", f"Секреты: найдено {q['secrets']['findings']}. В разметку они не входят и агенту не "
                  "передаются: разбирает человек."]
    return "\n".join(L)


# ---------------------------------------------------------------- проверка предложений
def _v(index: Optional[int], code: str, message: str) -> dict:
    return {"index": index, "code": code, "message": message}


def _read(path: Path) -> Tuple[Optional[dict], str, List[dict]]:
    """(содержимое, SHA-256 файла, нарушения формата на уровне файла)."""
    path = Path(path)
    if not path.is_file():
        raise ProposalError(f"нет файла предложений: {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > MAX_FILE_BYTES:
        return None, digest, [_v(None, "ПП01", f"файл больше {MAX_FILE_BYTES >> 10} КиБ")]
    try:
        data = yaml.load(raw.decode("utf-8"), Loader=_Loader)  # наследник SafeLoader
    except UnicodeDecodeError:
        return None, digest, [_v(None, "ПП01", "файл не в кодировке UTF-8")]
    except (yaml.YAMLError, RecursionError, ValueError) as e:
        why = getattr(e, "problem", "") or (str(e).splitlines() or [type(e).__name__])[0]
        return None, digest, [_v(None, "ПП01", f"не разбирается как YAML: {clean(why)[:200]}")]
    bad: List[dict] = []
    if not isinstance(data, dict):
        return None, digest, [_v(None, "ПП01", "ожидается отображение с ключами schema, meta, proposals")]
    if set(data) - _TOP_KEYS:
        bad.append(_v(None, "ПП01", f"неизвестные ключи: {', '.join(sorted(clean(k) for k in set(data) - _TOP_KEYS))}"))
    if data.get("schema") != SCHEMA:
        bad.append(_v(None, "ПП01", f"schema: ожидается {SCHEMA}"))
    meta = data.get("meta")
    if not isinstance(meta, dict):
        bad.append(_v(None, "ПП01", "meta: укажите agent (оболочка агента и версия) и model (модель и версия)"))
    else:
        if set(meta) - _META_KEYS:
            bad.append(_v(None, "ПП01", f"meta: неизвестные ключи: {', '.join(sorted(clean(k) for k in set(meta) - _META_KEYS))}"))
        for k in ("agent", "model"):
            if not isinstance(meta.get(k), str) or not meta[k].strip():
                bad.append(_v(None, "ПП01", f"meta.{k}: обязательная строка"))
        for k, val in meta.items():
            if k in _META_KEYS and not isinstance(val, (str, _dt.date)):
                bad.append(_v(None, "ПП01", f"meta.{k}: ожидается строка"))
            elif isinstance(val, str) and (len(val) > 200 or _hidden(val)):
                bad.append(_v(None, "ПП01", f"meta.{k}: длиннее 200 знаков или с управляющими символами"))
    props = data.get("proposals")
    if not isinstance(props, list):
        bad.append(_v(None, "ПП01", "proposals: ожидается список (может быть пустым)"))
        data = dict(data, proposals=[])
    elif len(props) > MAX_PROPOSALS:
        bad.append(_v(None, "ПП01", f"proposals: больше {MAX_PROPOSALS} предложений в одном файле"))
        data = dict(data, proposals=[])
    return data, digest, bad


def _shape(p) -> List[str]:
    """Ошибки формата одного предложения (ПП01); пустой список — можно проверять по существу."""
    if not isinstance(p, dict):
        return ["ожидается отображение"]
    kind = p.get("kind")
    if not isinstance(kind, str) or kind not in AGENT_VERDICTS:
        return [f"kind: {clean(kind)[:50]!r} (допустимо: {', '.join(AGENT_VERDICTS)})"]
    errs = []
    allowed = _COMMON_KEYS | set(_KIND_KEYS[kind])
    if set(p) - allowed:
        errs.append(f"неизвестные ключи: {', '.join(sorted(clean(k) for k in set(p) - allowed))}")
    for k in _KIND_KEYS[kind] + ("verdict", "reason"):
        if k not in p:
            errs.append(f"нет поля {k}")
    for k in ("id", "package", "version", "rule", "path", "verdict", "reason"):
        if k in p and k in allowed:
            if not isinstance(p[k], str) or not p[k].strip():
                errs.append(f"{k}: ожидается непустая строка" + (" в кавычках" if k == "version" else ""))
            elif len(p[k]) > MAX_TEXT or _hidden(p[k]):
                errs.append(f"{k}: длиннее {MAX_TEXT} знаков или с управляющими символами")
    if "line" in p and kind == "sast" and (isinstance(p["line"], bool) or not isinstance(p["line"], int)
                                           or p["line"] < 1):
        errs.append("line: ожидается номер строки")
    if isinstance(p.get("verdict"), str) and p["verdict"] != "accepted" and p["verdict"] not in AGENT_VERDICTS[kind]:
        errs.append(f"verdict: {clean(p['verdict'])!r} (допустимо: {', '.join(AGENT_VERDICTS[kind])})")
    refs = p.get("refs", [])
    if not isinstance(refs, list) or len(refs) > MAX_REFS:
        errs.append(f"refs: ожидается список не длиннее {MAX_REFS}")
        refs = []
    for n, r in enumerate(refs):
        if not isinstance(r, dict) or set(r) - _REF_KEYS or not {"path", "line", "quote"} <= set(r):
            errs.append(f"refs[{n}]: ожидаются поля path, line, quote и необязательное note")
        elif (not isinstance(r["path"], str) or isinstance(r["line"], bool) or not isinstance(r["line"], int)
              or r["line"] < 1 or not isinstance(r["quote"], str) or not isinstance(r.get("note", ""), str)):
            errs.append(f"refs[{n}]: path и quote — строки, line — номер строки")
        elif (len(r["path"]) > MAX_TEXT or len(r["quote"]) > MAX_TEXT or len(r.get("note", "")) > MAX_TEXT
              or _hidden(r["path"]) or _hidden(r["quote"]) or _hidden(r.get("note", ""))):
            errs.append(f"refs[{n}]: поле длиннее {MAX_TEXT} знаков или с управляющими символами")
    if "until" in p:
        try:
            _date(p["until"])
        except triage.TriageError as e:
            errs.append(str(e))
    return errs


def _date(v) -> Optional[_dt.date]:
    if isinstance(v, _dt.datetime):
        return v.date()
    if v is not None and not isinstance(v, (str, _dt.date)):
        raise triage.TriageError(f"until: {clean(v)} — ожидается дата ГГГГ-ММ-ДД")
    return triage._date(v)


def _match(p: dict, every: List[dict]) -> Tuple[Optional[dict], Optional[Tuple[str, str]]]:
    """Элемент комплекта, к которому относится предложение, или (код, пояснение)."""
    if p["kind"] == "vulnerability":
        same = [i for i in every if i["kind"] == "vulnerability" and i["package"] == p["package"]
                and (p["id"] == i["id"] or p["id"] in (i.get("aliases") or []))]
        if not same:
            return None, ("ПП02", f"в комплекте нет уязвимости {clean(p['id'])} в пакете {clean(p['package'])}")
        hit = [i for i in same if i["version"] == p["version"]]
        if not hit:
            have = ", ".join(sorted({i["version"] for i in same}))
            return None, ("ПП10", f"в комплекте {clean(p['package'])} версии {have}, в предложении {clean(p['version'])}")
        return hit[0], None
    same = [i for i in every if i["kind"] == "sast" and i["rule"] == p["rule"] and i["path"] == p["path"]]
    hit = [i for i in same if i["line"] == p["line"]]
    if not hit:
        hint = f" (в комплекте это правило в этом файле — строки {', '.join(sorted(str(i['line']) for i in same))})" \
            if same else ""
        return None, ("ПП02", f"в комплекте нет срабатывания {clean(p['rule'])} в {clean(p['path'])}:{p['line']}{hint}")
    return hit[0], None


def check_ref(ref: dict, root: Path, exclude: Optional[Path] = None) -> Optional[str]:
    """None, если цитата дословно найдена в указанных строках файла проекта; иначе причина.

    root — каталог проекта (уже приведённый resolve()); exclude — каталог комплекта свидетельств:
    ссылаться можно на код проекта, а не на отчёты инструментов и не на собственные файлы агента.
    """
    rel, quote = ref["path"], ref["quote"].strip("\n")
    if len("".join(quote.split())) < MIN_QUOTE:
        return f"цитата короче {MIN_QUOTE} знаков"
    want = quote.split("\n")
    if len(want) > MAX_QUOTE_LINES:
        return f"цитата длиннее {MAX_QUOTE_LINES} строк"
    pp = PurePosixPath(rel)
    if "\\" in rel or pp.is_absolute() or ".." in pp.parts or rel.startswith("~") or rel[1:2] == ":":
        return "путь должен быть относительным и лежать внутри проекта"
    if pp.parts and (pp.parts[0] == ".git" or pp.parts[0].startswith(".rbpo")):
        return "служебный каталог: ссылка должна вести на файл проекта"
    try:
        path = (root / rel).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return "путь выходит за пределы проекта"
    if exclude is not None and (path == exclude or exclude in path.parents):
        return "служебный каталог: ссылка должна вести на файл проекта"
    if not path.is_file():
        return "файла нет"
    if path.stat().st_size > MAX_SOURCE_BYTES:
        return f"файл больше {MAX_SOURCE_BYTES >> 20} МиБ"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    first, last = ref["line"], ref["line"] + len(want) - 1
    if last > len(lines):
        return f"в файле {len(lines)} строк"
    if _norm(quote) not in _norm(" ".join(lines[first - 1:last])):
        return "цитата не совпала с текстом файла в строках " + (str(first) if first == last else f"{first}–{last}")
    return None


def _check_one(n: int, p, every: List[dict], root: Path, exclude: Path, today: _dt.date, max_days: int,
               seen: set) -> Tuple[dict, List[dict]]:
    rec = {"index": n, "kind": None, "key": None, "label": "предложение не разобрано", "verdict": None,
           "status": None, "entry": None}
    shape = _shape(p)
    if shape:
        return rec, [_v(n, "ПП01", e) for e in shape]
    kind, verdict = p["kind"], p["verdict"]
    label = f"{p['id']} {p['package']} {p['version']}" if kind == "vulnerability" else \
        f"{p['rule']} {p['path']}:{p['line']}"
    rec.update(kind=kind, verdict=verdict, label=clean(f"{kind} {label}")[:300])
    bad: List[dict] = []
    if verdict == "accepted":
        bad.append(_v(n, "ПП04", "принятие риска решает владелец риска; предложите confirmed или оставьте элемент человеку"))
    wild = [k for k in _KIND_KEYS[kind] if isinstance(p[k], str) and any(c in p[k] for c in "*?[")]
    if wild:
        bad.append(_v(n, "ПП03", f"{', '.join(wild)}: нужно точное значение из очереди разметки"))
    else:
        item, miss = _match(p, every)
        if miss:
            bad.append(_v(n, *miss))
        else:
            rec.update(key=item["key"], status=item["status"])
            if item["key"] in seen:
                bad.append(_v(n, "ПП09", "по этому элементу уже есть предложение выше или в другом файле"))
            seen.add(item["key"])
            if item["verdict"] != "untriaged":
                bad.append(_v(n, "ПП11", f"в файле разметки уже есть решение {item['verdict']}; решения человека "
                                         "агент не пересматривает"))
    if len(p["reason"].strip()) < MIN_REASON:
        bad.append(_v(n, "ПП05", f"обоснование короче {MIN_REASON} знаков"))
    refs = p.get("refs", [])
    for k, r in enumerate(refs):
        why = check_ref(r, root, exclude)
        if why:
            bad.append(_v(n, "ПП07", f"refs[{k}] {clean(r['path'])}:{r['line']} — {why}"))
    clearing = verdict in CLEARING
    if clearing and not refs:
        bad.append(_v(n, "ПП06", f"{verdict} — нужна хотя бы одна ссылка на код: path, line, quote"))
    until = _date(p.get("until"))
    if clearing:
        if until is None:
            bad.append(_v(n, "ПП08", f"{verdict} без срока пересмотра (until)"))
        elif until < today:
            bad.append(_v(n, "ПП08", f"срок пересмотра {until.isoformat()} уже прошёл"))
        elif until > today + _dt.timedelta(days=max_days):
            bad.append(_v(n, "ПП08", f"срок пересмотра {until.isoformat()} дальше {max_days} дней от даты проверки"))
    if not bad:
        entry = {k: p[k] for k in (("id", "package") if kind == "vulnerability" else ("rule", "path", "line"))}
        entry.update(verdict=verdict, reason=_norm(p["reason"]))
        if until:
            entry["until"] = until.isoformat()
        rec["entry"] = entry
    return rec, bad


def _head(root: Path) -> str:
    try:
        return source.git(root, "rev-parse", "HEAD").strip()
    except (source.GitError, OSError):
        return ""


def check(files: Sequence[Path], out: Path, project: Path, today: Optional[_dt.date] = None,
          max_days: int = MAX_DAYS) -> dict:
    """Проверка файлов предложений по комплекту свидетельств out и файлам проекта project."""
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    out, root = Path(out), Path(project).resolve()
    every = _all_items(out)
    seen: set = set()
    reports: List[dict] = []
    proposed: Dict[str, str] = {}
    for f in files:
        data, digest, bad = _read(Path(f))
        recs: List[dict] = []
        for n, p in enumerate((data or {}).get("proposals", [])):
            rec, pb = _check_one(n, p, every, root, out.resolve(), today, max_days, seen)
            rec["ok"] = not pb
            recs.append(rec)
            bad += pb
            if rec["ok"]:
                proposed[rec["key"]] = rec["verdict"]
        meta = (data or {}).get("meta")
        meta = {clean(k): clean(v)[:200] for k, v in meta.items()} if isinstance(meta, dict) else {}
        reports.append({"file": str(f), "sha256": digest, "meta": meta, "proposals": recs, "violations": bad})
    blocking = [i for i in every if i["status"] == "blocking"]
    cleared = sum(1 for i in blocking if proposed.get(i["key"]) in CLEARING)
    confirmed = sum(1 for i in blocking if proposed.get(i["key"]) == "confirmed")
    n_all = sum(len(r["proposals"]) for r in reports)
    n_ok = sum(1 for r in reports for x in r["proposals"] if x["ok"])
    warnings = []
    ev_commit = (_load_json(out / "source" / "integrity.json") or {}).get("head", "")
    head = _head(root)
    if ev_commit and head and ev_commit != head:
        warnings.append(f"комплект свидетельств получен для коммита {ev_commit[:12]}, а проект сейчас на "
                        f"{head[:12]}: очередь могла устареть")
    if blocking and cleared == len(blocking):
        warnings.append(f"предложено снять все блокирующие элементы ({cleared}): проверьте каждое предложение особенно "
                        "внимательно")
    return {
        "schema": "rbpo-pipeline/proposals-check/v1",
        "checked": today.isoformat(),
        "limits": {"max_days": max_days, "min_reason": MIN_REASON, "min_quote": MIN_QUOTE},
        "commit": {"evidence": ev_commit, "project": head},
        "files": reports,
        "summary": {"proposals": n_all, "ok": n_ok, "rejected": n_all - n_ok,
                    "violations": sum(len(r["violations"]) for r in reports),
                    "blocking": len(blocking), "blocking_cleared": cleared, "blocking_confirmed": confirmed,
                    "blocking_without_proposal": len(blocking) - cleared - confirmed},
        "warnings": warnings,
        "ok": all(not r["violations"] for r in reports),
    }


def fragment(res: dict) -> str:
    """Предложения, прошедшие проверку, в формате файла разметки — для переноса человеком."""
    entries = [x for r in res["files"] for x in r["proposals"] if x["ok"]]
    doc = {"sast": [x["entry"] for x in entries if x["kind"] == "sast"],
           "vulnerabilities": [x["entry"] for x in entries if x["kind"] == "vulnerability"]}
    doc = {k: v for k, v in doc.items() if v}
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=110) if doc else ""


def _what(x: dict) -> str:
    return clean(f"{x['key'] or x['label']} → {x['verdict'] or '?'}")


def render_text(res: dict) -> str:
    s = res["summary"]
    L = [f"Проверка предложений агента на {res['checked']}: предложений {s['proposals']}, прошли проверку {s['ok']}, "
         f"отклонено {s['rejected']}",
         f"Блокирующих элементов в комплекте {s['blocking']}: предложено снять {s['blocking_cleared']}, "
         f"подтвердить {s['blocking_confirmed']}, без предложения {s['blocking_without_proposal']}"]
    for r in res["files"]:
        L += ["", f"{r['file']} (агент: {r['meta'].get('agent', '?')}; модель: {r['meta'].get('model', '?')})"]
        L += [f"  {v['code']} {RULES[v['code']]} — {clean(v['message'])}" for v in r["violations"] if v["index"] is None]
        for x in r["proposals"]:
            L.append(f"  [{x['index'] + 1}] {_what(x)}: " + ("прошло проверку" if x["ok"] else "отклонено"))
            L += [f"      {v['code']} {RULES[v['code']]} — {clean(v['message'])}"
                  for v in r["violations"] if v["index"] == x["index"]]
    if res["warnings"]:
        L += ["", "Предупреждения:"] + [f"  - {w}" for w in res["warnings"]]
    L += ["", NOTICE]
    return "\n".join(L)


def _cell(text) -> str:
    return clean(text).replace("|", "/").replace("`", "'")


def render_markdown(res: dict) -> str:
    """Отчёт для человека, который принимает решение; значения из файла предложений обезврежены."""
    s = res["summary"]
    L = ["## Проверка предложений агента по разметке", "",
         f"Дата проверки {res['checked']}. Предложений {s['proposals']}: прошли проверку {s['ok']}, "
         f"отклонено {s['rejected']}. Блокирующих элементов в комплекте {s['blocking']}: предложено снять "
         f"{s['blocking_cleared']}, подтвердить {s['blocking_confirmed']}, без предложения "
         f"{s['blocking_without_proposal']}.", "", f"**{NOTICE}**"]
    for w in res["warnings"]:
        L += ["", f"> Предупреждение: {w}"]
    for r in res["files"]:
        L += ["", f"### {_cell(r['file'])}", "",
              f"Агент: {_cell(r['meta'].get('agent', '?'))}; модель: {_cell(r['meta'].get('model', '?'))}; "
              f"SHA-256 файла: `{r['sha256']}`."]
        top = [f"- {v['code']} {RULES[v['code']]}: {_cell(v['message'])}" for v in r["violations"] if v["index"] is None]
        if top:
            L += [""] + top
        if r["proposals"]:
            L += ["", "| № | Элемент | Сейчас | Предложение | Проверка |", "|---|---|---|---|---|"]
        for x in r["proposals"]:
            codes = "; ".join(f"{v['code']} {_cell(v['message'])}" for v in r["violations"] if v["index"] == x["index"])
            L.append(f"| {x['index'] + 1} | {_cell(x['key'] or x['label'])} | {STATUS_RU.get(x['status'], '—')} | "
                     f"{_cell(x['verdict'] or '—')} | {codes or 'прошло'} |")
    frag = fragment(res)
    if frag:
        fence = "`" * (max([len(run) for run in _runs(frag)] + [2]) + 1)
        L += ["", "### Для переноса в файл разметки", "",
              "Предложения, прошедшие проверку, в формате `.rbpo/triage.yaml`. Переносит человек после того, "
              "как сам убедился в выводе; автор коммита с решением — человек.", "",
              f"{fence}yaml", frag.rstrip("\n"), fence]
    return "\n".join(L) + "\n"


def _runs(text: str) -> List[str]:
    """Серии обратных апострофов в тексте: ограждение блока кода должно быть длиннее любой из них."""
    res, cur = [], ""
    for c in text:
        if c == "`":
            cur += c
        elif cur:
            res.append(cur)
            cur = ""
    return res + ([cur] if cur else [])


# ---------------------------------------------------------------- контроль ветки агента
def guard(changes: Iterable[Tuple[str, str]], allowed: Sequence[str] = ALLOWED,
          modes: Optional[Dict[str, str]] = None) -> List[dict]:
    """Изменения, которых в ветке агента быть не должно.

    changes — пары (статус git, путь); allowed — шаблоны fnmatch, «*» захватывает и «/»; modes —
    режимы файлов в конечном коммите. В разрешённых путях агент только добавляет и меняет обычные файлы.
    """
    res = []
    for status, path in changes:
        if not any(fnmatchcase(path, a) for a in allowed):
            res.append({"path": path, "status": status, "reason": "вне разрешённых путей"})
        elif status[:1] not in ("A", "M"):
            res.append({"path": path, "status": status, "reason": "файлы предложений не удаляются и не меняют тип"})
        elif modes is not None and modes.get(path) != "100644":
            res.append({"path": path, "status": status,
                        "reason": f"не обычный файл (режим {modes.get(path, 'неизвестен')})"})
    return sorted(res, key=lambda x: x["path"])


def guard_range(project: Path, base: str, head: str = "HEAD", allowed: Optional[Sequence[str]] = None) -> dict:
    """Проверка диапазона base...head: изменения ветки относительно точки её ответвления от base."""
    for name, rev in (("base", base), ("head", head)):
        if not rev or rev.startswith("-"):  # значение не должно читаться git как ключ командной строки
            raise ProposalError(f"{name}: ожидается ветка или коммит")
    project = Path(project).resolve()
    top = Path(source.git(project, "rev-parse", "--show-toplevel").strip()).resolve()
    prefix = "" if project == top else project.relative_to(top).as_posix() + "/"
    # Записи «:старый_режим новый_режим старый_объект новый_объект статус» и путь, разделённые NUL.
    parts = source.git(top, "diff", "--raw", "--no-renames", "-z", f"{base}...{head}").split("\0")
    changes, modes = [], {}
    for info, path in zip(parts[0::2], parts[1::2]):
        _, new_mode, _, _, status = info.lstrip(":").split(" ")
        changes.append((status, path))
        modes[path] = new_mode
    patterns = [prefix + a for a in (allowed or ALLOWED)]
    return {"base": base, "head": source.git(top, "rev-parse", head).strip(), "allowed": patterns,
            "changed": len(changes), "violations": guard(changes, patterns, modes)}


def render_guard(res: dict) -> str:
    if not res["violations"]:
        return (f"Ветка агента: изменено файлов {res['changed']}, все в разрешённых путях "
                f"({', '.join(res['allowed'])})")
    L = [f"Ветка агента меняет то, что агенту менять нельзя ({len(res['violations'])} из {res['changed']} путей):"]
    L += [clean(f"  {v['status']:<2} {v['path']} — {v['reason']}") for v in res["violations"]]
    L += ["Разрешено: " + ", ".join(res["allowed"])]
    return "\n".join(L)
