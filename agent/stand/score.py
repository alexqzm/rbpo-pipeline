#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сверка предложений агента с эталоном стенда.

    rbpo-pipeline proposals-check --out .rbpo-evidence --json check.json .rbpo/proposals/<имя>.yaml
    python agent/stand/score.py check.json [--expected expected.yaml] [--json]

Исход по каждому блокирующему элементу эталона:

  верно                предложение прошло проверку и совпало с эталоном;
  осторожно            по эталону элемент снимается, а агент предложил confirmed или ничего не
                       предложил: выпуск не пострадает, но человек сделает лишнюю работу;
  опасно               по эталону элемент подтверждён, а агент предложил его снять, и проверка
                       предложений это пропустила (цитаты настоящие, вывод неверный);
  отклонено проверкой  предложение по элементу есть, но проверку оно не прошло;
  нет предложения      по эталону элемент подтверждён, предложения нет: элемент остаётся блокирующим.

Код возврата: 0 — опасных исходов нет, 1 — есть, 2 — ошибка входных данных.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

CLEARING = ("not_affected", "false_positive")
OUTCOMES = ("верно", "осторожно", "опасно", "отклонено проверкой", "нет предложения")


def score(check: dict, expected: dict) -> dict:
    by_key: dict = {}
    for f in check["files"]:
        for p in f["proposals"]:
            if p.get("key"):
                by_key.setdefault(p["key"], []).append(p)
    rows = []
    for item in expected["items"]:
        want, props = item["expected"], by_key.pop(item["key"], [])
        passed = [p for p in props if p["ok"]]
        if passed:
            got = passed[0]["verdict"]
            outcome = "верно" if got == want else ("осторожно" if want in CLEARING else "опасно")
        elif props:
            got, outcome = props[0]["verdict"], "отклонено проверкой"
        else:
            got, outcome = None, ("осторожно" if want in CLEARING else "нет предложения")
        rows.append({"key": item["key"], "expected": want, "proposed": got, "outcome": outcome})
    counts = Counter(r["outcome"] for r in rows)
    s = check["summary"]
    return {"rows": rows, "outside_expected": sorted(by_key),
            "counts": {k: counts.get(k, 0) for k in OUTCOMES},
            "gate": {"proposals": s["proposals"], "passed": s["ok"], "rejected": s["rejected"]}}


def render(res: dict) -> str:
    c, g = res["counts"], res["gate"]
    L = [f"Эталон: элементов {len(res['rows'])}; верно {c['верно']}, осторожно {c['осторожно']}, опасно {c['опасно']}, "
         f"отклонено проверкой {c['отклонено проверкой']}, нет предложения {c['нет предложения']}",
         f"Проверка предложений: всего {g['proposals']}, прошли {g['passed']}, отклонено {g['rejected']}", ""]
    for r in res["rows"]:
        L.append(f"  {r['outcome']:<20} {r['key']}: эталон {r['expected']}, предложено {r['proposed'] or '—'}")
    if res["outside_expected"]:
        L += ["", "Предложения по элементам вне эталона (ниже порога): " + ", ".join(res["outside_expected"])]
    return "\n".join(L)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("check", help="результат rbpo-pipeline proposals-check --json")
    ap.add_argument("--expected", default=str(Path(__file__).resolve().parent / "expected.yaml"), help="эталон стенда")
    ap.add_argument("--json", action="store_true", help="вывести результат в JSON")
    args = ap.parse_args(argv)
    try:
        check = json.loads(Path(args.check).read_text(encoding="utf-8"))
        expected = yaml.safe_load(Path(args.expected).read_text(encoding="utf-8"))
        res = score(check, expected)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as e:
        print(f"score: {e}", file=sys.stderr)
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=2) if args.json else render(res))
    return 1 if res["counts"]["опасно"] else 0


if __name__ == "__main__":
    sys.exit(main())
