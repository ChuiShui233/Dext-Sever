#!/usr/bin/env python3
"""
merge_sql.py
把 目录下(不含 _migrations/ 子目录)的所有 .sql 文件
按文件名分类优先级合并到一个文件,供云数据库一次性导入。

约定:
- 真正属于"全新库一次导入"的 schema 文件请直接放在 SQL_DIR 根目录
- 历史迁移 / 老库修复 / 数据策略脚本请放在 _migrations/ 子目录,本脚本会跳过

文件名优先级(数字越小越先合并):
1. database_schema.sql         (主 schema)
2. create_*.sql                (额外的 CREATE TABLE)
3. add_*_*.sql / add_*.sql     (ALTER 加表加列)
4. 其它(若没有破坏性语法)

跳过规则:
- 含 PREPARE/EXECUTE/DEALLOCATE 的文件会被跳过(部分导入工具走 prepared
  statement 协议,会 ERROR 1295)
- CREATE/DROP INDEX IF [NOT] EXISTS 会被替换为占位注释(MySQL 8.0 之前不支持)

环境变量:
- MERGE_KEEP_DB_META=1     保留 CREATE DATABASE / USE
- MERGE_KEEP_PREPARED=1    不过滤 PREPARE 文件
- MERGE_SKIP_DROP=1        不生成重置段(不要 DROP TABLE)
- MERGE_OUTPUT=path        自定义输出文件
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# ---------- 配置 ----------
SQL_DIR = Path(r"i:\Dext-Sever\SQL")
ARCHIVE_DIR_NAME = "_migrations"
DEFAULT_OUTPUT = SQL_DIR / "merged_all.sql"

# 需要过滤掉的元信息
DB_CREATE_RE = re.compile(r"^\s*CREATE\s+DATABASE\b[^;]*;\s*$", re.IGNORECASE | re.MULTILINE)
DB_USE_RE = re.compile(r"^\s*USE\s+[^;]+;\s*$", re.IGNORECASE | re.MULTILINE)

# 触发跳过的关键字
PREPARED_RE = re.compile(r"\b(PREPARE|EXECUTE|DEALLOCATE)\b", re.IGNORECASE)

# 识别 / 替换的索引语法
DROP_INDEX_IF_EXISTS_RE = re.compile(
    r"^\s*DROP\s+INDEX\s+IF\s+EXISTS\s+.+?;\s*$",
    re.IGNORECASE | re.MULTILINE,
)
CREATE_INDEX_IF_NOT_EXISTS_RE = re.compile(
    r"^\s*CREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+.+?;\s*$",
    re.IGNORECASE | re.MULTILINE,
)
CREATE_TABLE_RE = re.compile(
    r"^\s*CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?(?P<name>\w+)`?\s*\(",
    re.IGNORECASE | re.MULTILINE,
)

PRIORITY = {
    "database_schema": 10,
    "create_": 20,
    "add_": 30,
    "migrate_": 40,
    "fix_": 50,
    "complete_": 60,
    "session_": 70,
    "oauth_email_conflict": 80,
    "multi_email": 90,
    "data_merge": 100,
    "check_": 110,
}


def priority(name: str) -> int:
    n = name.lower()
    for prefix, p in PRIORITY.items():
        if n.startswith(prefix):
            return p
    return 999


def strip_db_meta(content: str) -> str:
    """移除 CREATE DATABASE / USE 语句。"""
    out: list[str] = []
    for line in content.splitlines(keepends=True):
        if DB_CREATE_RE.match(line) or DB_USE_RE.match(line):
            continue
        out.append(line)
    return "".join(out)


def strip_mariadb_only_index_syntax(content: str) -> str:
    """把 MariaDB 专属的 IF [NOT] EXISTS 索引语法替换为占位注释。"""
    content = DROP_INDEX_IF_EXISTS_RE.sub(
        "-- [stripped: MariaDB-only DROP INDEX IF EXISTS]\n", content
    )
    content = CREATE_INDEX_IF_NOT_EXISTS_RE.sub(
        "-- [stripped: MariaDB-only CREATE INDEX IF NOT EXISTS]\n", content
    )
    return content


def strip_comments(content: str) -> str:
    """
    去掉 -- 单行注释和 /* */ 块注释,避免注释里出现 PREPARE/EXECUTE/DEALLOCATE
    字样导致误判。
    """
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    lines: list[str] = []
    for line in content.splitlines(keepends=True):
        idx = line.find("--")
        if idx == -1:
            lines.append(line)
            continue
        lines.append(line[:idx].rstrip() + "\n" if line.endswith("\n") else line[:idx].rstrip())
    return "".join(lines)


def uses_prepared(content: str) -> bool:
    return bool(PREPARED_RE.search(strip_comments(content)))


def collect_files(sql_dir: Path) -> list[Path]:
    """收集根目录下的 .sql 文件(归档子目录 _migrations/ 跳过)。"""
    archive = sql_dir / ARCHIVE_DIR_NAME
    out: list[Path] = []
    for p in sorted(sql_dir.glob("*.sql")):
        if not p.is_file():
            continue
        out.append(p)
    out = [p for p in out if archive not in p.parents]
    out.sort(key=lambda p: (priority(p.stem), p.name.lower()))
    return out


def merge() -> None:
    if not SQL_DIR.is_dir():
        print(f"[ERR] 目录不存在: {SQL_DIR}", file=sys.stderr)
        sys.exit(1)

    output = Path(os.environ["MERGE_OUTPUT"]) if os.environ.get("MERGE_OUTPUT") else DEFAULT_OUTPUT
    files = collect_files(SQL_DIR)
    files = [p for p in files if p.name != output.name]
    if not files:
        print("[WARN] 未发现 .sql 文件")
        return

    keep_meta = os.environ.get("MERGE_KEEP_DB_META") == "1"
    keep_prepared = os.environ.get("MERGE_KEEP_PREPARED") == "1"
    skip_drop = os.environ.get("MERGE_SKIP_DROP") == "1"

    sections: list[str] = []
    skipped_prepared: list[str] = []
    included: list[Path] = []
    tables_in_order: list[str] = []  # 按出现顺序收集,后面反向 DROP

    for fp in files:
        raw = fp.read_text(encoding="utf-8")
        if not keep_prepared and uses_prepared(raw):
            skipped_prepared.append(fp.name)
            continue
        included.append(fp)
        body = raw if keep_meta else strip_db_meta(raw)
        body = strip_mariadb_only_index_syntax(body)

        # 抓 CREATE TABLE 表名(去重保序)
        for m in CREATE_TABLE_RE.finditer(body):
            t = m.group("name").strip("`")
            if t and t not in tables_in_order:
                tables_in_order.append(t)

        div = "-- " + "-" * 70
        sections.append(
            f"\n{div}\n-- >>> Source: {fp.name}\n{div}\n\n{body.rstrip()}\n"
        )

    # 反向 DROP(子表先于父表,避免外键约束)
    drop_block = ""
    if tables_in_order and not skip_drop:
        drop_lines = [
            f"DROP TABLE IF EXISTS `{t}`;"
            for t in reversed(tables_in_order)
        ]
        drop_block = (
            "-- 0) 重置段: 反向 DROP TABLE IF EXISTS,清掉老残留,确保干净重建。\n"
            + "\n".join(drop_lines)
            + "\n"
        )

    top_div = "-- " + "-" * 58
    skip_note = (
        ""
        if not skipped_prepared
        else "-- 已跳过(含 PREPARE/EXECUTE):\n"
        + "".join(f"--   - {n}\n" for n in skipped_prepared)
        + "-- 它们已迁移到 " + ARCHIVE_DIR_NAME + "/ 目录,如需老库升级请手动跑。\n"
    )
    merged = (
        f"{top_div}\n"
        "-- Merged SQL (generated by merge_sql.py)\n"
        f"-- Files merged : {len(included)} / {len(files)}\n"
        f"-- Source dir   : {SQL_DIR}\n"
        "-- 导入前请确保当前连接已切换到目标数据库(如: USE your_db;)\n"
        "-- 保留 CREATE DATABASE / USE 设 MERGE_KEEP_DB_META=1\n"
        "-- 关闭重置段(不要 DROP)设 MERGE_SKIP_DROP=1\n"
        f"{skip_note}"
        f"{top_div}\n\n"
        f"{drop_block}"
        + "".join(sections)
    )

    output.write_text(merged, encoding="utf-8")
    print(f"[OK] 合并完成: {len(included)}/{len(files)} -> {output}")
    if skipped_prepared:
        print(f"[INFO] 跳过 {len(skipped_prepared)} 个: {', '.join(skipped_prepared)}")
    if tables_in_order and not skip_drop:
        print(f"[INFO] 重置段: 反向 DROP {len(tables_in_order)} 张表")

    _sanity_check(output, tables_in_order)


def _sanity_check(output: Path, tables: list[str]) -> None:

    text = output.read_text(encoding="utf-8")
    placeholders = re.findall(r"\b\w*(?:dummy|placeholder|tmp_)\w*\b", text, re.IGNORECASE)
    real_bad = [p for p in placeholders if p.lower() not in {"placeholder"}]
    real_bad = [p for p in real_bad if "_dummy" in p.lower() or "_tmp" in p.lower() or p.lower().endswith("_dummy")]
    if real_bad:
        print(f"\n[FAIL] 合并文件里出现可疑占位名: {set(real_bad)}")
        print("       这通常是上游 SQL 笔误(例:user_id_dummy),会导致 MySQL 1072/1054。")
        print("       请检查源 SQL 后重新 merge。\n")
        sys.exit(2)

    table_blocks: dict[str, set[str]] = {}
    current: str | None = None
    cols: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"\s*CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?(\w+)`?\s*\(", line, re.IGNORECASE)
        if m:
            if current:
                table_blocks[current] = cols
            current = m.group(1).lower()
            cols = set()
            continue
        if current and re.search(r"^\s*\)\s*ENGINE", line, re.IGNORECASE):
            cols.add(current)
            table_blocks[current] = cols
            current = None
            cols = set()
            continue
        if current:
            cm = re.match(r"\s*`?(\w+)`?\s+(?:VARCHAR|INT|BIGINT|TINYINT|TEXT|DATETIME|TIMESTAMP|JSON|BOOLEAN|DECIMAL|FLOAT|DOUBLE|CHAR|ENUM)", line, re.IGNORECASE)
            if cm:
                c = cm.group(1).lower()
                if c.upper() not in {"PRIMARY", "FOREIGN", "INDEX", "KEY", "UNIQUE", "CONSTRAINT", "CHECK"}:
                    cols.add(c)

    bad_idx: list[str] = []
    for line in text.splitlines():
        m = re.match(r"\s*INDEX\s+(\w+)\s*\(\s*(\w+)\s*\)", line, re.IGNORECASE)
        if not m:
            continue
        idx_name, col = m.group(1).lower(), m.group(2).lower()
        if "_" in col and col in table_blocks:
            continue
        if not any(col in cs for cs in table_blocks.values()):
            bad_idx.append(f"  {idx_name}({col}) 不属于任何已知表的列")

    if bad_idx:
        print(f"\n[WARN] 下列 INDEX 引用了未声明的列(可能是表块扫描漏判,需人工复核):")
        for b in bad_idx:
            print(b)


if __name__ == "__main__":
    merge()
