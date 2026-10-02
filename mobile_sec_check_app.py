#!/usr/bin/env python3
import html
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from mobile_sec_check import scan_target


PAGE = """<!doctype html>
<meta charset="utf-8">
<title>KCP Mobile Security Check</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:32px;line-height:1.5;max-width:860px}}
input{{font-size:16px;padding:10px;width:100%;box-sizing:border-box}}
button{{font-size:16px;padding:10px 16px;margin-top:12px}}
.hint{{color:#666}}.err{{color:#b00020}}.ok{{color:#0a7f35}}
</style>
<h1>KCP Mobile Security Check</h1>
<p class="hint">점검할 IPA / APK / AAB의 전체 경로를 넣으세요.</p>
<form action="/scan" method="post">
  <input name="target" placeholder="/Users/user/src/.../KCPWallet.ipa" autofocus>
  <button>점검 시작</button>
</form>
{message}
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.render("")

    def do_POST(self):
        if urlparse(self.path).path != "/scan":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        params = parse_qs(self.rfile.read(length).decode())
        target = Path(params.get("target", [""])[0].strip()).expanduser()
        if not target.exists():
            self.render(f'<p class="err">파일이 없습니다: {html.escape(str(target))}</p>')
            return
        try:
            stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            out_dir = Path.home() / "KCP보안점검" / f"{target.stem}_{stamp}"
            report = scan_target(target, out_dir)
        except Exception as exc:
            self.render(f'<p class="err">점검 실패: {html.escape(str(exc))}</p>')
            return
        url = report.resolve().as_uri()
        webbrowser.open(url)
        self.render(f'<p class="ok">점검 완료: <a href="{html.escape(url)}">{html.escape(str(report))}</a></p>')

    def render(self, message):
        data = PAGE.format(message=message).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        return


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    host, port = server.server_address
    url = f"http://{host}:{port}"
    print(url)
    threading.Timer(0.2, lambda: webbrowser.open(url)).start()
    server.serve_forever()


if __name__ == "__main__":
    main()
