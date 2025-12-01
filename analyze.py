from __future__ import annotations

import argparse
import json
import os
import subprocess
import textwrap
import time
from pathlib import Path
from typing import Dict, List, Optional

try:
    import requests
except ImportError:  # pragma: no cover - dependency check
    requests = None


# ========= 하드코딩안된 LLM 설정 =========
OPENAI_API_KEY = "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"  # 여기에 실제 API 키를 입력하세요
OPENAI_MODEL = "gpt-4o-mini"          # 원하는 모델명으로 변경 가능
OPENAI_API_BASE = "https://api.openai.com/v1"  # OpenAI 호환 엔드포인트
# =====================================


def run(cmd: List[str], cwd: Optional[Path] = None) -> None:
    """Run a command and raise on failure."""
    res = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}"
        )


def decompile(apk_path: Path, out_dir: Path) -> Path:
    """Run jadx to decompile the APK. Uses `jadx -d <out_dir> <apk>`."""
    if out_dir.exists() and any(out_dir.iterdir()):
        raise FileExistsError(
            f"{out_dir} already exists and is not empty. Remove or rename it first."
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    run(["jadx", "-d", str(out_dir), str(apk_path)])
    return out_dir


def find_manifest(out_dir: Path) -> Optional[Path]:
    """Find AndroidManifest.xml in common locations under the jadx output."""
    candidates = [
        out_dir / "AndroidManifest.xml",
        out_dir / "resources" / "AndroidManifest.xml",
        out_dir / "manifest.xml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def parse_manifest(manifest_path: Path) -> Dict[str, object]:
    """Parse basic manifest info (package, permissions, exported components)."""
    import xml.etree.ElementTree as ET  # local import to avoid global dependency

    info: Dict[str, object] = {
        "package": "",
        "permissions": [],
        "exported_components": [],
    }
    try:
        tree = ET.parse(manifest_path)
    except Exception as exc:
        info["error"] = f"Failed to parse manifest: {exc}"
        return info

    root = tree.getroot()
    info["package"] = root.attrib.get("package", "")

    perms: List[str] = []
    for perm in root.findall("uses-permission"):
        name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
        if name:
            perms.append(name)
    info["permissions"] = perms

    exported: List[str] = []
    for tag in ("activity", "service", "receiver", "provider"):
        for node in root.findall(tag):
            name = node.attrib.get("{http://schemas.android.com/apk/res/android}name")
            exported_flag = node.attrib.get(
                "{http://schemas.android.com/apk/res/android}exported"
            )
            has_filter = node.find("intent-filter") is not None
            if exported_flag == "true" or has_filter:
                exported.append(f"{tag}:{name}")
    info["exported_components"] = exported
    return info


def iter_candidate_files(
    root: Path,
    include_smali: bool = True,
    limit: Optional[int] = None,
    max_bytes: Optional[int] = None,
    package_name: Optional[str] = None,
    exclude_libs: bool = True,
) -> List[Path]:
    """
    Choose interesting files:
    - By extension (.java, .kt, optionally .smali).
    - Optionally under max_bytes size.
    - Prefer app package paths; optionally exclude common library prefixes.
    - No keyword filtering; include all non-library files.
    """
    exts = {".java", ".kt"}
    if include_smali:
        exts.add(".smali")
    candidates: List[tuple[int, int, int, Path]] = []
    package_path = package_name.replace(".", "/") if package_name else None
    lib_prefixes = [
        "android/support",
        "android/arch",
        "androidx",
        "com/google/android",
        "com/google/gson",
        "com/google/firebase",
        "com/google/protobuf",
        "com/squareup",
        "okhttp3",
        "retrofit2",
        "org/apache",
        "org/json",
        "org/bouncycastle",
        "kotlin",
        "java/",
        "javax",
    ]

    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if max_bytes is not None and size > max_bytes:
            continue
        rel = path.relative_to(root).as_posix()
        base = path.name
        if base.startswith("R$") or base in {"R.java", "BuildConfig.java"}:
            continue
        is_lib = any(rel.startswith(prefix) for prefix in lib_prefixes)
        if exclude_libs and is_lib:
            continue
        is_app_pkg = package_path and rel.startswith(package_path)
        lib_flag = 1 if is_lib else 0
        app_rank = 0 if is_app_pkg else 1
        candidates.append((lib_flag, app_rank, size, path))

    candidates.sort(key=lambda item: (item[0], item[1], -item[2]))
    sliced = candidates if limit is None else candidates[:limit]
    return [p for _, _, _, p in sliced]


def load_snippet(path: Path, max_chars: int = 8000) -> str:
    """Read a file with a safe size cap; include head and tail when trimmed."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2 :]
    return head + "\n...\n" + tail


def build_prompt(
    manifest_info: Dict[str, object], rel_path: str, code_snippet: str
) -> List[Dict[str, str]]:
    """Create chat messages for the LLM request."""
    manifest_summary = json.dumps(manifest_info, ensure_ascii=False)
    system_prompt = (
        "You are an Android reverse engineer. "
        "Given a decompiled source file, map out per-function behavior, data/control flow, "
        "and key interactions. Return strict JSON."
    )
    user_prompt = textwrap.dedent(
        f"""
        Context:
        - Manifest info: {manifest_summary}
        - File: {rel_path}

        Task:
        - File-level: purpose, key entry points (lifecycle/handlers/exported/constructors), important state/static fields/constants/strings, and interactions with other app classes.
        - For each function/method: purpose, inputs, outputs/state changes, notable behaviors (network/storage/IPC/UI/crypto/WebView/reflection/native), control-flow triggers, data flow (sources -> sinks), calls/dependencies, and any state it reads/writes.
        - Skip trivial getters/setters/constants unless relevant.
        - Provide short tips to further reverse this file (where to hook/patch, values to tamper, edge cases).

        Output JSON schema:
        {{
          "file": "{rel_path}",
          "summary": {{
            "primary_purpose": "<one short sentence>",
            "key_points": ["<bullet>"],
            "entry_points": ["<methods called externally or lifecycle hooks>"],
            "state": ["<static fields/constants/important members>"]
          }},
          "functions": [
            {{
              "name": "<function or method>",
              "purpose": "<short>",
              "inputs": ["<param/source>"],
              "outputs": ["<return/state change>"],
              "calls": ["<APIs/classes/functions>"],
              "side_effects": ["<UI/state/IO/IPC>"],
              "control_flow": ["<conditions/triggers>"],
              "data_flow": ["<from -> to>"],
              "state_changes": ["<fields mutated or read>"],
              "notable_behaviors": ["<bullet>"],
              "notes": ["<edge cases or TODO>"]
            }}
          ],
          "guideline": ["<short tips for further reversing this file>"]
        }}

        Code:
        ```
        {code_snippet}
        ```
        """
    ).strip()
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


class OpenAIClient:
    """Minimal OpenAI-compatible chat completions client using requests."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        timeout: int = 60,
    ) -> None:
        if requests is None:
            raise SystemExit(
                "The 'requests' package is required. Install with: pip install requests"
            )
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def chat(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(
                f"LLM request failed: {resp.status_code} {resp.text}"
            )
        data = resp.json()
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content")
        if not content:
            raise RuntimeError(f"Empty LLM response: {data}")
        return content


def write_reports(out_dir: Path, results: List[Dict[str, object]]) -> None:
    """Persist JSON and Markdown reports."""
    json_path = out_dir / "analysis.json"
    md_path = out_dir / "analysis.md"

    with json_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    lines = ["# APK Analysis Report", ""]
    for item in results:
        file_path = item.get("file", "")
        summary = item.get("summary", {}) or {}
        primary = summary.get("primary_purpose", "") or item.get("primary_purpose", "")
        key_points = summary.get("key_points", []) or []
        entry_points = summary.get("entry_points", []) or []
        state_items = summary.get("state", []) or []
        functions = item.get("functions", []) or []
        guideline = item.get("guideline", []) or []

        lines.append(f"## {file_path}")
        if primary:
            lines.append(f"- Purpose: {primary}")
        if key_points:
            lines.append("- Key points:")
            for r in key_points:
                lines.append(f"  - {r}")
        if entry_points:
            lines.append("- Entry points:")
            for ep in entry_points:
                lines.append(f"  - {ep}")
        if state_items:
            lines.append("- State/constants:")
            for st in state_items:
                lines.append(f"  - {st}")
        if functions:
            lines.append("- Functions:")
            for fn in functions:
                name = fn.get("name", "")
                lines.append(f"  - {name}:")
                purpose = fn.get("purpose", "")
                if purpose:
                    lines.append(f"    - purpose: {purpose}")
                inputs = fn.get("inputs", []) or []
                if inputs:
                    lines.append(f"    - inputs: {', '.join(inputs)}")
                outputs = fn.get("outputs", []) or []
                if outputs:
                    lines.append(f"    - outputs: {', '.join(outputs)}")
                calls = fn.get("calls", []) or []
                if calls:
                    lines.append(f"    - calls: {', '.join(calls)}")
                side_effects = fn.get("side_effects", []) or []
                if side_effects:
                    lines.append("    - side_effects:")
                    for s in side_effects:
                        lines.append(f"      - {s}")
                control_flow = fn.get("control_flow", []) or []
                if control_flow:
                    lines.append("    - control_flow:")
                    for c in control_flow:
                        lines.append(f"      - {c}")
                data_flow = fn.get("data_flow", []) or []
                if data_flow:
                    lines.append("    - data_flow:")
                    for d in data_flow:
                        lines.append(f"      - {d}")
                state_changes = fn.get("state_changes", []) or []
                if state_changes:
                    lines.append("    - state_changes:")
                    for sc in state_changes:
                        lines.append(f"      - {sc}")
                beh = fn.get("notable_behaviors", []) or []
                if beh:
                    lines.append("    - notable:")
                    for b in beh:
                        lines.append(f"      - {b}")
                notes = fn.get("notes", []) or []
                if notes:
                    lines.append("    - notes:")
                    for n in notes:
                        lines.append(f"      - {n}")
        if guideline:
            lines.append("- Guideline:")
            for g in guideline:
                lines.append(f"  - {g}")
        lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved {json_path} and {md_path}")


def analyze_files(
    client: OpenAIClient,
    root: Path,
    files: List[Path],
    manifest_info: Dict[str, object],
) -> List[Dict[str, object]]:
    """Send each file to the LLM and collect structured responses."""
    results: List[Dict[str, object]] = []
    for idx, path in enumerate(files, 1):
        rel_path = str(path.relative_to(root))
        snippet = load_snippet(path)
        messages = build_prompt(manifest_info, rel_path, snippet)
        print(f"[{idx}/{len(files)}] Analyzing {rel_path} ...", flush=True)
        try:
            content = client.chat(messages)
            parsed = json.loads(content)
        except Exception as exc:
            parsed = {
                "file": rel_path,
                "error": f"Failed to parse LLM response: {exc}",
                "raw_response": content if "content" in locals() else "",
            }
        results.append(parsed)
        time.sleep(0.1)  # gentle pacing
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto Android reverse engineering via LLM (hardcoded API settings)"
    )
    parser.add_argument("apk", type=Path, help="Path to APK file")
    args = parser.parse_args()

    # 환경변수 대신 하드코딩 값 사용
    api_key = OPENAI_API_KEY
    model = OPENAI_MODEL
    api_base = OPENAI_API_BASE

    if not api_key:
        raise SystemExit(
            "OPENAI_API_KEY 상수에 API 키를 설정한 후 다시 실행해 주세요."
        )

    apk_path: Path = args.apk
    if not apk_path.exists():
        raise SystemExit(f"APK not found: {apk_path}")

    out_dir: Path = Path(f"{apk_path.stem}_out")
    src_root = out_dir / "sources"
    if src_root.exists():
        print(f"Reusing existing decompile at {out_dir}")
    else:
        print(f"Decompiling {apk_path} with jadx into {out_dir} ...")
        decompile(apk_path, out_dir)

    if not src_root.exists():
        raise SystemExit(f"Expected sources at {src_root}, not found.")

    manifest_path = find_manifest(out_dir)
    if manifest_path:
        manifest_info = parse_manifest(manifest_path)
        print(f"Loaded manifest: {manifest_path}")
    else:
        manifest_info = {"package": "", "permissions": [], "exported_components": []}
        print("Warning: Manifest not found.")

    files = iter_candidate_files(
        src_root,
        include_smali=True,
        limit=None,
        max_bytes=None,
        package_name=manifest_info.get("package") if isinstance(manifest_info, dict) else None,
        exclude_libs=True,
    )
    if not files:
        raise SystemExit("No candidate files found.")

    print("Candidate files (ranked):")
    for path in files:
        print(f"- {path.relative_to(src_root)}")

    client = OpenAIClient(
        api_key=api_key, model=model, base_url=api_base
    )
    results = analyze_files(client, src_root, files, manifest_info)
    write_reports(out_dir, results)
    print("Done.")


if __name__ == "__main__":
    main()
