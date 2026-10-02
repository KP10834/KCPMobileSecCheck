#!/usr/bin/env python3
import argparse
import hashlib
import html
import json
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path


SECRET_PATTERNS = [
    ("PEM-PRIVATE-KEY", re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("AWS-ACCESS-KEY", re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GOOGLE-API-KEY", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GITHUB-TOKEN", re.compile(rb"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("JWT", re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
]

CHECKLIST = {
    "ios": [
        ("MOB-FIN-011", "[전자금융] OS 변조 탐지 기능 적용", ["IOS-JAILBREAK"]),
        ("MOB-FIN-020", "[전자금융] 소스코드 난독화 적용", ["IOS-ANTIDEBUG", "RN-APPGUARD"]),
        ("MOB-FIN-021", "[전자금융] 디버깅 탐지기능 적용", ["IOS-ANTIDEBUG", "IOS-GET-TASK-ALLOW"]),
        ("MOB-SER-025", "앱 소스코드 내 운영정보 노출 방지", ["CMN-SECRET", "CMN-HARDCODED-KEY"]),
        ("MOB-SER-043", "백그라운드 화면 보호", ["IOS-BG-SNAPSHOT"]),
    ],
    "aos": [
        ("MOB-FIN-011", "[전자금융] OS 변조 탐지 기능 적용", ["RN-APPGUARD"]),
        ("MOB-FIN-012", "[전자금융] 악성코드 방지", ["RN-APPGUARD"]),
        ("MOB-FIN-018", "[전자금융] 프로그램 무결성 검증", ["AND-SIGN-SCHEME"]),
        ("MOB-FIN-021", "[전자금융] 디버깅 탐지기능 적용", ["AND-DEBUGGABLE"]),
        ("MOB-SER-025", "앱 소스코드 내 운영정보 노출 방지", ["CMN-SECRET", "CMN-HARDCODED-KEY"]),
    ],
    "rn": [
        ("RN-001", "React Native bundle 보호", ["RN-BUNDLE-EXISTS"]),
        ("RN-002", "NHN AppGuard React Native 보호 작업 적용", ["RN-APPGUARD"]),
    ],
}

STATUS_LABELS = {
    "pass": "양호",
    "fail": "취약",
    "manual": "수동확인필요",
    "missing": "수동확인필요",
}

STATUS_MARKS = {"pass": "○", "fail": "✕", "manual": "△", "missing": "△"}
STATUS_CLASSES = {"pass": "pass", "fail": "fail", "manual": "manual", "missing": "manual"}

ITEM_DESCRIPTIONS = {
    "MOB-FIN-011": "변조된 OS를 통한 서비스 이용 방지 여부 점검. 루팅·탈옥 단말에서는 보안 프로그램 무력화와 결제 우회가 가능해집니다.",
    "MOB-FIN-012": "악성코드, 원격제어, 자동화 도구 등 비정상 실행 환경 탐지 여부를 확인합니다.",
    "MOB-FIN-018": "앱 위변조, 서명 스킴, 무결성 검증 적용 여부를 확인합니다.",
    "MOB-FIN-020": "디컴파일을 통한 소스코드 분석 시 난독화 또는 보호 솔루션 적용 여부를 확인합니다.",
    "MOB-FIN-021": "디버깅을 통한 역분석을 방지하기 위한 안티디버깅 적용 여부를 확인합니다.",
    "MOB-SER-025": "앱 소스코드 내 서버 계정, 고정 암호키, 토큰 등 운영정보 노출 여부를 확인합니다.",
    "MOB-SER-043": "백그라운드 전환 시 스냅샷에 중요 정보가 노출되는지 확인합니다.",
    "RN-001": "React Native 번들 존재 여부와 번들 보호 필요성을 확인합니다.",
    "RN-002": "NHN AppGuard React Native 보호 작업 적용 흔적을 확인합니다.",
}

ITEM_FIXES = {
    "MOB-FIN-011": "AppGuard 정책에서 Rooting/Jailbreak 탐지를 활성화하고 실제 변조 단말에서 차단 동작을 확인합니다.",
    "MOB-FIN-012": "AppGuard 정책에서 Cheating Tool, RemoteControl, MacroTool 등 비정상 환경 탐지를 활성화합니다.",
    "MOB-FIN-018": "배포 서명본 기준으로 AppGuard 보호 산출물을 사용하고, 위변조 탐지 정책을 활성화합니다.",
    "MOB-FIN-020": "AppGuard 보호 산출물을 기준으로 제출하고, 필요 시 JS bundle 보호 및 문자열 보호 여부를 추가 확인합니다.",
    "MOB-FIN-021": "배포본에서 debug/profile 설정을 끄고, AppGuard Debugger 탐지 정책을 활성화합니다.",
    "MOB-SER-025": "빌드 산출물에 운영 키·토큰·내부 URL이 포함되지 않도록 환경값을 서버 또는 안전한 저장소로 분리합니다.",
    "MOB-SER-043": "앱 전환 시 민감 화면을 블러 또는 오버레이로 가리고 캡처/녹화 탐지를 적용합니다.",
}


def status(ok, evidence, manual=False):
    if manual:
        return {"status": "manual", "evidence": evidence}
    return {"status": "pass" if ok else "fail", "evidence": evidence}


def run(cmd):
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout


def strings(path):
    code, out = run(["strings", "-a", str(path)])
    return out if code == 0 else ""


def scan_secrets(root):
    hits = []
    for path in root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 20_000_000:
            continue
        data = path.read_bytes()
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                hits.append({"pattern": name, "file": str(path.relative_to(root))})
    return hits


def entitlements(app_path):
    code, out = run(["codesign", "-d", "--entitlements", ":-", str(app_path)])
    if code != 0 or "<?xml" not in out:
        return {}, out.strip()
    xml = out[out.find("<?xml") :].encode()
    try:
        return plistlib.loads(xml), ""
    except Exception as exc:
        return {}, f"entitlements parse failed: {exc}"


def scan_ipa(target):
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        with zipfile.ZipFile(target) as zf:
            zf.extractall(work)
        apps = list((work / "Payload").glob("*.app"))
        if not apps:
            return {"platform": "ios", "target": str(target), "error": "Payload/*.app not found"}
        app = apps[0]
        plist_path = app / "Info.plist"
        info = plistlib.loads(plist_path.read_bytes()) if plist_path.exists() else {}
        exe = app / info.get("CFBundleExecutable", app.name.removesuffix(".app"))
        text = strings(exe) if exe.exists() else ""
        ent, ent_error = entitlements(app)
        secret_hits = scan_secrets(app)
        bundle = app / "main.jsbundle"
        return {
            "platform": "ios",
            "target": str(target),
            "package": info.get("CFBundleIdentifier", "-"),
            "version": info.get("CFBundleShortVersionString", "-"),
            "probes": {
                "IOS-GET-TASK-ALLOW": status(
                    ent.get("get-task-allow") is not True,
                    ent_error or ("get-task-allow is not true" if ent.get("get-task-allow") is not True else "get-task-allow=true"),
                    manual=bool(ent_error),
                ),
                "IOS-ANTIDEBUG": status(
                    any(token in text for token in ["ptrace", "PT_DENY_ATTACH", "P_TRACED", "sysctl"]),
                    "anti-debug string found" if any(token in text for token in ["ptrace", "PT_DENY_ATTACH", "P_TRACED", "sysctl"]) else "anti-debug string not found",
                ),
                "IOS-JAILBREAK": status(
                    any(token in text for token in ["Cydia.app", "/bin/bash", "/usr/sbin/sshd", "MobileSubstrate"]),
                    "jailbreak indicator string found" if any(token in text for token in ["Cydia.app", "/bin/bash", "/usr/sbin/sshd", "MobileSubstrate"]) else "jailbreak indicator string not found",
                ),
                "IOS-BG-SNAPSHOT": status(
                    any(token in text for token in ["UIBlurEffect", "UIApplicationUserDidTakeScreenshotNotification", "isCaptured"]),
                    "background/capture protection string found" if any(token in text for token in ["UIBlurEffect", "UIApplicationUserDidTakeScreenshotNotification", "isCaptured"]) else "background/capture protection string not found",
                    manual=True,
                ),
                "RN-BUNDLE-EXISTS": status(bundle.exists(), "main.jsbundle found" if bundle.exists() else "main.jsbundle not found"),
                "RN-APPGUARD": status(
                    any(token in text for token in ["Diresu", "AppGuard", "NHNAppGuardVersion"]),
                    "AppGuard string found" if any(token in text for token in ["Diresu", "AppGuard", "NHNAppGuardVersion"]) else "AppGuard string not found",
                ),
                "CMN-SECRET": status(not secret_hits, f"{len(secret_hits)} secret-like hits"),
                "CMN-HARDCODED-KEY": status(True, "not implemented separately", manual=True),
            },
            "entitlements_error": ent_error,
            "secret_hits": secret_hits[:50],
        }


def scan_android(target):
    with zipfile.ZipFile(target) as zf:
        names = set(zf.namelist())
        is_aab = target.suffix.lower() == ".aab"
        manifest = "base/manifest/AndroidManifest.xml" if is_aab else "AndroidManifest.xml"
        manifest_data = zf.read(manifest) if manifest in names else b""
    package = android_package_name(manifest_data)
    version = android_version_name(manifest_data)
    appguard_found = "appguard" in target.name.lower() or any("appguard" in name.lower() for name in names)
    return {
        "platform": "aos",
        "target": str(target),
        "package": package or "-",
        "version": version or "-",
        "probes": {
            "AND-MANIFEST": status(manifest in names, f"{manifest} {'found' if manifest in names else 'not found'}"),
            "RN-BUNDLE-EXISTS": status(
                any(name.endswith("index.android.bundle") for name in names),
                "index.android.bundle found" if any(name.endswith("index.android.bundle") for name in names) else "index.android.bundle not found",
            ),
            "AND-SIGN-SCHEME": status(False, "use apksigner for APK; AAB signing check not implemented", manual=True),
            "AND-DEBUGGABLE": status(False, "binary AndroidManifest parse not implemented", manual=True),
            "RN-APPGUARD": status(
                appguard_found,
                "AppGuard artifact found" if appguard_found else "AppGuard artifact not found",
            ),
        },
    }


def android_package_name(manifest_data):
    text = manifest_data.decode("latin1", errors="ignore")
    candidates = re.findall(r"\b[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+\b", text)
    for candidate in candidates:
        if candidate.startswith("com.") and not candidate.startswith("com.android."):
            return candidate
    return candidates[0] if candidates else ""


def android_version_name(manifest_data):
    text = manifest_data.decode("latin1", errors="ignore")
    match = re.search(r"\b\d+\.\d+(?:\.\d+)?\b", text)
    return match.group(0) if match else ""


def write_report(result, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    page = render_html_report(result)
    (out_dir / "report.html").write_text(page, encoding="utf-8")


def render_html_report(result):
    items = checklist_items(result)
    counts = {key: sum(1 for item in items if status_class(item["status"]) == key) for key in ["fail", "manual", "pass"]}
    generated_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    target = Path(result.get("target", "-"))
    package = result.get("package") or target.stem
    platform = result.get("platform", "-")
    version = result.get("version", "-")
    size = file_size(target)
    digest = sha256_short(target)
    toc = "".join(
        f'<a class="sub" href="#{esc(item["id"])}"><span class="dot {status_class(item["status"])}"></span><span>{esc(item["title"])}</span></a>'
        for item in items
    )
    rows = "\n".join(render_item_row(item) for item in items)

    page = f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>보안 점검 리포트 — KCP Wallet</title>
<style>
:root{{
  --bg:#ffffff; --fg:#18181b; --muted:#6b7280; --line:#e4e4e7; --card:#fafafa;
  --accent:#2563eb; --fail:#dc2626; --pass:#16a34a; --manual:#d97706; --na:#9ca3af;
  color-scheme: light;
}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Pretendard","Apple SD Gothic Neo",sans-serif}}
.layout{{display:grid;grid-template-columns:248px minmax(0,1fr);max-width:1240px;margin:0 auto;align-items:start}}
.toc{{position:sticky;top:0;height:100vh;overflow-y:auto;padding:28px 16px 40px;border-right:1px solid var(--line);background:var(--card)}}
.toc .toc-title,.toc a.toc-sec{{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:0 0 12px;padding:0 8px}}
.toc a.toc-sec{{display:block;margin:0;text-decoration:none}}
.toc a{{display:block;padding:5px 8px;border-radius:6px;color:var(--fg);text-decoration:none;font-size:13px;line-height:1.4}}
.toc a:hover{{background:color-mix(in srgb,var(--accent) 10%,transparent)}}
.toc a.sub{{padding-left:20px;font-size:12.5px;color:var(--muted);display:flex;gap:6px;align-items:baseline}}
.toc a.sub:hover{{color:var(--fg)}}.toc .sec{{margin-top:16px}}
.dot{{flex:0 0 auto;width:7px;height:7px;border-radius:50%;margin-top:5px}}
.dot.fail{{background:var(--fail)}}.dot.pass{{background:var(--pass)}}.dot.manual{{background:var(--manual)}}.dot.na{{background:var(--na)}}
.main{{padding:40px 32px 96px;min-width:0}}
@media (max-width:860px){{.layout{{grid-template-columns:1fr}}.toc{{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}}.main{{padding:24px 16px 64px}}}}
h1{{font-size:26px;margin:0 0 4px;letter-spacing:-.02em}}h2{{font-size:19px;margin:44px 0 14px;letter-spacing:-.01em}}
.sub{{color:var(--muted);font-size:13px;margin-bottom:28px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-bottom:28px}}
.meta div{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}}
.meta dt{{font-size:11px;color:var(--muted);margin:0 0 3px;text-transform:uppercase;letter-spacing:.04em}}.meta dd{{margin:0;font-size:14px;word-break:break-all;font-variant-numeric:tabular-nums}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:10px;margin-bottom:12px}}
.tile{{border:1px solid var(--line);border-radius:10px;padding:14px;background:var(--card)}}.tile .n{{font-size:26px;font-weight:650;line-height:1;font-variant-numeric:tabular-nums}}.tile .l{{font-size:12px;color:var(--muted);margin-top:5px}}
.tile.fail .n{{color:var(--fail)}}.tile.pass .n{{color:var(--pass)}}.tile.manual .n{{color:var(--manual)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11.5px;font-weight:600;white-space:nowrap}}.badge .mk{{margin-right:4px;font-weight:700}}
.badge.fail{{background:color-mix(in srgb,var(--fail) 14%,transparent);color:var(--fail)}}.badge.pass{{background:color-mix(in srgb,var(--pass) 14%,transparent);color:var(--pass)}}.badge.manual{{background:color-mix(in srgb,var(--manual) 16%,transparent);color:var(--manual)}}
.rows-hint{{margin-bottom:10px}}.rowtools{{display:flex;gap:8px;justify-content:flex-end;margin:0 0 9px}}
.rowtools button{{border:1px solid var(--line);background:var(--card);color:var(--muted);border-radius:7px;padding:5px 11px;font:inherit;font-size:12.5px;cursor:pointer}}.rowtools button:hover{{color:var(--fg);border-color:var(--muted)}}
.rows{{border:1px solid var(--line);border-radius:10px;overflow:hidden}}.rhead,.row>summary{{display:grid;grid-template-columns:14px 92px minmax(0,1fr);gap:12px;align-items:center;padding:10px 14px}}
.rhead{{background:var(--card);border-bottom:1px solid var(--line);font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}}
.row{{border-bottom:1px solid var(--line)}}.row:last-child{{border-bottom:none}}.row>summary{{cursor:pointer;list-style:none}}.row>summary::-webkit-details-marker{{display:none}}.row>summary:hover{{background:color-mix(in srgb,var(--fg) 4%,transparent)}}.row[open]>summary{{background:color-mix(in srgb,var(--fg) 3%,transparent);border-bottom:1px solid var(--line)}}.row:target>summary{{background:color-mix(in srgb,var(--accent) 10%,transparent)}}
.row .chev{{width:0;height:0;border-left:5px solid var(--muted);border-top:4px solid transparent;border-bottom:4px solid transparent;transition:transform .12s}}.row[open] .chev{{transform:rotate(90deg)}}.row .t{{font-weight:600;min-width:0;overflow-wrap:anywhere}}.row .body{{padding:2px 18px 20px 40px;background:var(--card);border-top:none}}
.desc{{color:var(--muted);font-size:13.5px;margin:12px 0 4px}}.probe{{margin:15px 0 4px;font-size:13px}}.probe .pid{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--muted)}}
.ev{{border-left:2px solid var(--line);padding:9px 0 9px 13px;margin:11px 0}}.ev .w{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted)}}.ev .d{{margin-top:3px}}
.fix{{background:color-mix(in srgb,var(--pass) 8%,transparent);border-radius:8px;padding:11px 13px;margin-top:13px;font-size:13.5px}}.fix b{{color:var(--pass)}}
footer{{margin-top:48px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}}
@media (max-width:860px){{.rhead{{display:none}}.row>summary{{grid-template-columns:14px minmax(0,1fr);row-gap:5px}}.row>summary .chev{{grid-column:1;grid-row:1}}.row>summary .vd{{grid-column:2;grid-row:1}}.row>summary .t{{grid-column:2;grid-row:2}}.row .body{{padding:2px 14px 18px}}}}
</style>
</head><body><div class="layout"><nav class="toc"><div class="toc-title">목차</div><a href="#overview">개요</a><a href="#summary">판정 요약</a><div class="sec"><a class="toc-sec" href="#items-table">점검 항목</a></div>{toc}</nav><main class="main"><h1 id="overview">모바일 앱 보안 취약점 점검 리포트</h1><div class="sub">KCP Wallet · {esc(platform.upper())} · 점검 {esc(generated_at)} · 엔진 v0.1.0</div><div class="meta"><div><dt>패키지</dt><dd>{esc(package)}</dd></div><div><dt>버전</dt><dd>{esc(version)}</dd></div><div><dt>플랫폼</dt><dd>{esc(platform)}</dd></div><div><dt>파일</dt><dd>{esc(target.name)}</dd></div><div><dt>크기</dt><dd>{esc(size)}</dd></div><div><dt>SHA-256</dt><dd>{esc(digest)}</dd></div><div><dt>minSdk / targetSdk</dt><dd>- / -</dd></div><div><dt>서명 스킴</dt><dd>-</dd></div></div><h2 id="summary">판정 요약</h2><div class="tiles"><div class="tile fail"><div class="n">{counts["fail"]}</div><div class="l">✕ 취약</div></div><div class="tile manual"><div class="n">{counts["manual"]}</div><div class="l">△ 수동확인필요</div></div><div class="tile pass"><div class="n">{counts["pass"]}</div><div class="l">○ 양호</div></div></div><h2 id="items-table">점검 항목</h2><p class="sub rows-hint">행을 클릭하면 판정 근거와 조치 방법이 펼쳐집니다.</p><div class="rowtools"><button type="button" id="expand-all">모두 펼치기</button><button type="button" id="collapse-all">모두 접기</button></div><div class="rows"><div class="rhead"><span></span><span>판정</span><span>제목</span></div>{rows}</div><footer>점검 도구: KCPMobileSecCheck<br>판정은 취약 · 수동확인필요 · 양호 세 가지입니다. 자동으로 판정이 서지 않은 항목은 수동확인필요로 묶습니다.<br>'양호' 판정은 해당 취약점이 없다는 증명이 아니라 정적 증거가 발견되지 않았다는 뜻이며, 실행 중 동작은 동적 점검으로 별도 확인해야 합니다.</footer><script>
(function(){{
  var rows=document.querySelectorAll('.row');
  function setAll(v){{rows.forEach(function(r){{r.open=v}});}}
  document.getElementById('expand-all').addEventListener('click',function(){{setAll(true)}});
  document.getElementById('collapse-all').addEventListener('click',function(){{setAll(false)}});
  function openHash(){{if(!location.hash)return;var el=document.getElementById(decodeURIComponent(location.hash.slice(1)));if(el&&el.tagName==='DETAILS'){{el.open=true;el.scrollIntoView({{block:'center'}});}}}}
  window.addEventListener('hashchange',openHash);openHash();
}})();
</script></main></div></body></html>
"""
    return page


def checklist_items(result):
    platform = result.get("platform", "")
    probes = result.get("probes", {})
    rows = CHECKLIST.get(platform, []) + CHECKLIST["rn"]
    items = []
    for item_id, title, probe_names in rows:
        statuses = [probes.get(name, {"status": "missing", "evidence": "probe not implemented"}) for name in probe_names]
        item_status = summarize_status(status["status"] for status in statuses)
        items.append({
            "id": item_id,
            "title": title,
            "status": item_status,
            "probes": [(name, probes.get(name, {"status": "missing", "evidence": "probe not implemented"})) for name in probe_names],
        })
    return items


def summarize_status(statuses):
    ordered = list(statuses)
    if "fail" in ordered:
        return "fail"
    if "manual" in ordered:
        return "manual"
    if "missing" in ordered:
        return "missing"
    return "pass"


def render_item_row(item):
    probes = "\n".join(render_probe(name, data) for name, data in item["probes"])
    fix = ITEM_FIXES.get(item["id"], "수동 확인 결과에 따라 보호 정책 또는 빌드 설정을 보완합니다.")
    return f"""
<details class="row" id="{esc(item["id"])}">
  <summary><span class="chev" aria-hidden="true"></span><span class="vd">{badge(item["status"])}</span><span class="t">{esc(item["title"])}</span></summary>
  <div class="body"><div class="desc">{esc(ITEM_DESCRIPTIONS.get(item["id"], ""))}</div>{probes}<div class="fix"><b>조치 방법</b><br>{esc(fix)}</div></div>
</details>
    """


def render_probe(name, data):
    return f'<div class="probe">{badge(data["status"])} <span class="pid">{esc(name)}</span></div><div class="ev"><div class="w">정적 점검</div><div class="d">{esc(data["evidence"])}</div></div>'


def badge(status_name):
    css = status_class(status_name)
    mark = STATUS_MARKS.get(status_name, "△")
    label = STATUS_LABELS.get(status_name, status_name)
    return f'<span class="badge {esc(css)}"><span class="mk">{esc(mark)}</span>{esc(label)}</span>'


def status_class(status_name):
    return STATUS_CLASSES.get(status_name, status_name)


def file_size(path):
    try:
        size = path.stat().st_size
    except OSError:
        return "-"
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024


def sha256_short(path):
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "-"
    return f"{digest[:32]}…"


def esc(value):
    return html.escape(str(value))


def scan(args):
    report = scan_target(Path(args.target), Path(args.out))
    print(report)


def scan_target(target, out_dir):
    if target.suffix.lower() == ".ipa":
        result = scan_ipa(target)
    elif target.suffix.lower() in {".apk", ".aab"}:
        result = scan_android(target)
    else:
        raise SystemExit("target must be .ipa, .apk, or .aab")
    write_report(result, out_dir)
    return out_dir / "report.html"


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("target")
    scan_parser.add_argument("--out", default="out/mobile-sec-check")
    scan_parser.set_defaults(func=scan)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
