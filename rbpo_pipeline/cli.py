# -*- coding: utf-8 -*-
"""Командная строка rbpo-pipeline: шаги конвейера пишут свидетельства в каталог --out.

  install-tools   скачать закреплённые инструменты и проверить SHA-256
  env             сведения о сборочной среде                       5.12.3.2
  source          изменения в диапазоне и целостность кода           5.4.3.3, 5.14.3.3
  sast            отчёт статического анализа с разметкой             5.10.3.2–5.10.3.4
  sca             перечень зависимостей и известные уязвимости       5.16.3.2, 5.16.3.4
  secrets         итог поиска секретов                               (решение по выпуску)
  av              антивирусная проверка заимствованного кода          5.17.3.5
  tests           отчёт и журнал функционального тестирования        5.18.3.2, 5.18.3.3
  org             организационные документы из rbpo.yaml
  build-run       сборка с журналом и контрольными суммами           5.13.3.4
  store-verify    результаты из хранилища совпадают с собранными     5.13.3.5
  repro           повторная сборка дала те же результаты             5.13.3.6
  attest-verify   проверка аттестаций происхождения                  5.20.3.4
  assemble        анализ неустранённых ошибок (5.20.3.2), манифест, отчёт rbpo-evidence, опись, решение
  decision        код возврата по решению: 0 — выпуск допустим, 1 — нет

Работа с ИИ-агентом (docs/agent.md): агент предлагает разметку, решение принимает человек.

  triage-queue    очередь разметки: что в комплекте свидетельств ждёт решения
  proposals-check проверка предложений агента по разметке            0 — нарушений нет, 1 — есть
  agent-guard     ветка агента меняет только каталог предложений     0 — нарушений нет, 1 — есть

Коды возврата: 0 — успешно, 2 — ошибка входных данных; build-run возвращает код команды сборки.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__, analysis, assemble, build, config, envinfo, org, proposals, source, tools, triage
from .states import put_state, write_json


def _out(args) -> Path:
    p = Path(args.out)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _adopt(out: Path, src, subdir: str):
    """Файл внутри каталога свидетельств как есть; снаружи — копируется в out/subdir/."""
    if not src:
        return None
    src = Path(src)
    if not src.exists():
        return src
    try:
        src.resolve().relative_to(out.resolve())
        return src
    except ValueError:
        dest = out / subdir / src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        return dest


def _cfg(args) -> dict:
    return config.load(args.config)


def _triage(args, cfg) -> list:
    p = Path(args.project) / cfg["triage"]
    return triage.load(p)


def cmd_install_tools(args) -> int:
    only = [x for x in (args.only or "").split(",") if x]
    res = tools.install(Path(args.dest), only or None, Path(args.cache) if args.cache else None)
    for name, path in res.items():
        print(f"{name}: {path}")
    return 0


def cmd_env(args) -> int:
    envinfo.collect(_out(args))
    return 0


def cmd_source(args) -> int:
    out, cfg = _out(args), _cfg(args)
    event = {}
    ep = os.environ.get("GITHUB_EVENT_PATH")
    if ep and Path(ep).exists():
        event = json.loads(Path(ep).read_text(encoding="utf-8"))
    source.collect(out, Path(args.project), os.environ.get("GITHUB_REPOSITORY", ""),
                   os.environ.get("GITHUB_EVENT_NAME", ""), event, os.environ.get("GITHUB_REF", ""),
                   cfg["policy"]["commit_signatures"], use_api=not args.no_api)
    return 0


def cmd_sast(args) -> int:
    out, cfg = _out(args), _cfg(args)
    sarif = _adopt(out, args.sarif, "sast")
    if not Path(sarif).exists() or args.exit_code not in (None, 0, 1):
        why = (f"Semgrep завершился с кодом {args.exit_code}" if args.exit_code not in (None, 0, 1)
               else "нет отчёта SARIF")
        for aid in ("5.10.3.2", "5.10.3.3", "5.10.3.4"):
            put_state(out, aid, "N", [], {"exit_code": args.exit_code}, f"статический анализ не выполнен: {why}",
                      "semgrep", error=args.exit_code is not None)
        return 0
    analysis.sast(out, sarif, _adopt(out, args.json, "sast"), args.config_name, cfg["policy"]["sast_fail_on"],
                  _triage(args, cfg), Path(args.project), cfg["sast_exclude_languages"])
    return 0


def cmd_sca(args) -> int:
    out, cfg = _out(args), _cfg(args)
    sbom = _adopt(out, args.sbom, "sca")
    if not Path(sbom).exists() or args.sbom_exit_code not in (None, 0):
        err = args.sbom_exit_code is not None
        why = f"Syft завершился с кодом {args.sbom_exit_code}" if args.sbom_exit_code not in (None, 0) else "нет SBOM"
        put_state(out, "5.16.3.2", "N", [], {}, f"перечень зависимостей не сформирован: {why}", "syft", error=err)
        put_state(out, "5.16.3.4", "N", [], {}, "анализ известных уязвимостей не выполнялся: нет SBOM", "grype",
                  error=err)
        return 0
    grype = _adopt(out, args.grype, "sca")
    ok = grype is not None and Path(grype).exists() and args.grype_exit_code in (None, 0)
    analysis.sca(out, sbom, grype if ok else None, cfg["policy"]["sca_fail_on"], _triage(args, cfg))
    if not ok and args.grype_exit_code not in (None, 0):
        put_state(out, "5.16.3.4", "N", [], {"exit_code": args.grype_exit_code},
                  f"анализ известных уязвимостей не выполнен: Grype завершился с кодом {args.grype_exit_code}",
                  "grype", error=True)
    return 0


def cmd_secrets(args) -> int:
    out, cfg = _out(args), _cfg(args)
    analysis.secrets(out, _adopt(out, args.report, "secrets"), args.exit_code, cfg["policy"]["secrets"])
    return 0


def cmd_av(args) -> int:
    out = _out(args)
    analysis.av(out, _adopt(out, args.log, "av"), args.exit_code, args.target or [])
    return 0


def cmd_tests(args) -> int:
    out = _out(args)
    analysis.tests(out, _adopt(out, args.junit, "tests"), _adopt(out, args.log, "tests"), args.exit_code)
    return 0


def cmd_org(args) -> int:
    out, cfg = _out(args), _cfg(args)
    _check_ids(cfg["organizational"])
    org.collect(out, Path(args.project), cfg["organizational"], assemble.AUTOMATED)
    return 0


def _check_ids(ids) -> None:
    from rbpo_evidence.model import Model
    model = Model.load(None)
    bad = [a for a in ids if a not in model.artifact]
    if bad:
        raise config.ConfigError(f"organizational: неизвестные артефакты: {', '.join(bad)}")


def cmd_build_run(args) -> int:
    return build.run(_out(args), args.role, args.command, Path(args.project), args.dist, args.clean)


def cmd_store_verify(args) -> int:
    storage = {k: v for k, v in (("artifact_id", args.artifact_id), ("artifact_url", args.artifact_url),
                                 ("artifact_digest", args.artifact_digest)) if v}
    build.store_verify(_out(args), Path(args.dist), Path(args.sums), storage)
    return 0


def cmd_repro(args) -> int:
    build.repro(_out(args), Path(args.build), Path(args.rebuild))
    return 0


def cmd_attest_verify(args) -> int:
    build.attest_verify(_out(args), Path(args.dist), args.repo, args.signer_workflow, args.source_digest, args.skip)
    return 0


def cmd_assemble(args) -> int:
    out, cfg = _out(args), _cfg(args)
    needs = json.loads(os.environ.get(args.needs_env, "") or "{}") if args.needs_env else None
    res = assemble.assemble(out, cfg, needs)
    print(json.dumps(res, ensure_ascii=False))
    return 0


def cmd_decision(args) -> int:
    p = Path(args.out) / "decision.json"
    if not p.exists():
        print("нет decision.json: сначала выполните assemble", file=sys.stderr)
        return 2
    dec = json.loads(p.read_text(encoding="utf-8"))
    if dec["decision"] == "pass":
        print("выпуск допустим")
        return 0
    print("выпуск не допускается:")
    for r in dec["reasons"]:
        print(f"  - {r}")
    return 1


def cmd_triage_queue(args) -> int:
    q = proposals.queue(Path(args.out))
    if args.json:
        write_json(Path(args.json), q)
    print(proposals.render_queue(q))
    return 0


def cmd_proposals_check(args) -> int:
    today = _dt.date.fromisoformat(args.date) if args.date else None
    res = proposals.check([Path(p) for p in args.proposals], Path(args.out), Path(args.project), today,
                          args.max_days)
    if args.json:
        write_json(Path(args.json), res)
    if args.md:
        Path(args.md).write_text(proposals.render_markdown(res), encoding="utf-8")
    print(proposals.render_text(res))
    return 0 if res["ok"] else 1


def cmd_agent_guard(args) -> int:
    res = proposals.guard_range(Path(args.project), args.base, args.head, args.allow)
    print(proposals.render_guard(res))
    return 1 if res["violations"] else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rbpo-pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"rbpo-pipeline {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_, project=False, cfg=False):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--out", default=".rbpo-evidence", help="каталог свидетельств")
        if project:
            p.add_argument("--project", default=".", help="каталог проекта")
        if cfg:
            p.add_argument("--config", default="rbpo.yaml", help="настройки проекта")
        p.set_defaults(func=func)
        return p

    p = sub.add_parser("install-tools", help="скачать закреплённые инструменты")
    p.add_argument("--dest", required=True)
    p.add_argument("--only", help="через запятую: syft,grype,gitleaks")
    p.add_argument("--cache", help="каталог с уже скачанными архивами")
    p.set_defaults(func=cmd_install_tools)

    add("env", cmd_env, "сведения о сборочной среде")
    p = add("source", cmd_source, "изменения и целостность исходного кода", project=True, cfg=True)
    p.add_argument("--no-api", action="store_true", help="не обращаться к GitHub API за проверкой подписей")
    p = add("sast", cmd_sast, "отчёт статического анализа", project=True, cfg=True)
    p.add_argument("--sarif", required=True)
    p.add_argument("--json", help="JSON-вывод Semgrep (разобранные файлы)")
    p.add_argument("--config-name", default="", help="набор правил анализатора")
    p.add_argument("--exit-code", type=int, help="код завершения анализатора")
    p = add("sca", cmd_sca, "перечень зависимостей и известные уязвимости", project=True, cfg=True)
    p.add_argument("--sbom", required=True)
    p.add_argument("--grype")
    p.add_argument("--sbom-exit-code", type=int, help="код завершения Syft")
    p.add_argument("--grype-exit-code", type=int, help="код завершения Grype")
    p = add("secrets", cmd_secrets, "итог поиска секретов", cfg=True)
    p.add_argument("--report")
    p.add_argument("--exit-code", type=int)
    p = add("av", cmd_av, "антивирусная проверка")
    p.add_argument("--log")
    p.add_argument("--exit-code", type=int)
    p.add_argument("--target", action="append", help="что проверялось (можно несколько)")
    p = add("tests", cmd_tests, "функциональное тестирование")
    p.add_argument("--junit")
    p.add_argument("--log")
    p.add_argument("--exit-code", type=int)
    add("org", cmd_org, "организационные документы", project=True, cfg=True)
    p = add("build-run", cmd_build_run, "сборка с журналом", project=True)
    p.add_argument("--role", choices=("build", "rebuild"), default="build")
    p.add_argument("--command", required=True)
    p.add_argument("--dist", default="dist")
    p.add_argument("--clean", action="store_true", help="очистить каталог результатов перед сборкой")
    p = add("store-verify", cmd_store_verify, "сверка результатов из хранилища")
    p.add_argument("--dist", required=True)
    p.add_argument("--sums", required=True)
    p.add_argument("--artifact-id")
    p.add_argument("--artifact-url")
    p.add_argument("--artifact-digest")
    p = add("repro", cmd_repro, "сравнение двух сборок")
    p.add_argument("--build", required=True)
    p.add_argument("--rebuild", required=True)
    p = add("attest-verify", cmd_attest_verify, "проверка аттестаций происхождения")
    p.add_argument("--dist", required=True)
    p.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    p.add_argument("--signer-workflow", default="")
    p.add_argument("--source-digest", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--skip", default="", help="причина, по которой проверка не выполняется")
    p = add("assemble", cmd_assemble, "комплект свидетельств и решение", cfg=True)
    p.add_argument("--needs-env", default="", help="переменная окружения с toJSON(needs)")
    add("decision", cmd_decision, "код возврата по решению")

    p = add("triage-queue", cmd_triage_queue, "очередь разметки: что в комплекте ждёт решения")
    p.add_argument("--json", help="записать очередь в файл JSON (для агента)")
    p = add("proposals-check", cmd_proposals_check, "проверка предложений агента по разметке", project=True)
    p.add_argument("proposals", nargs="+", help="файлы предложений (.rbpo/proposals/*.yaml)")
    p.add_argument("--max-days", type=int, default=proposals.MAX_DAYS,
                   help="наибольший срок пересмотра снимающего решения, дней")
    p.add_argument("--date", help="дата проверки ГГГГ-ММ-ДД (по умолчанию сегодня, UTC)")
    p.add_argument("--json", help="записать результат в файл JSON")
    p.add_argument("--md", help="записать отчёт для человека в файл Markdown")
    p = sub.add_parser("agent-guard", help="ветка агента меняет только каталог предложений")
    p.add_argument("--project", default=".", help="каталог проекта")
    p.add_argument("--base", required=True, help="ветка или коммит, от которого ответвилась ветка агента")
    p.add_argument("--head", default="HEAD", help="проверяемый коммит")
    p.add_argument("--allow", action="append",
                   help="разрешённый шаблон пути относительно каталога проекта (можно несколько)")
    p.set_defaults(func=cmd_agent_guard)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (config.ConfigError, triage.TriageError, build.BuildError, tools.ToolError, source.GitError,
            ValueError) as e:
        print(f"rbpo-pipeline: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
