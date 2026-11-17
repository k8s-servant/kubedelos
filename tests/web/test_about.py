import json
import re
from datetime import timedelta

import kubedelos
from kubedelos.trivy.pins import TRIVY_VERSION


def _dbs(app, tmp_path, *, updated_h=3, next_h=21, java=True):
    app.state.settings = app.state.settings.model_copy(update={"cache_dir": tmp_path / "cache"})
    now = app.state.clock()
    for name in ("db", "java-db") if java else ("db",):
        meta = tmp_path / "cache" / "trivy-cache" / name / "metadata.json"
        meta.parent.mkdir(parents=True, exist_ok=True)
        meta.write_text(json.dumps({
            "UpdatedAt": (now - timedelta(hours=updated_h)).isoformat(),
            "NextUpdate": (now + timedelta(hours=next_h)).isoformat(),
            "DownloadedAt": (now - timedelta(hours=1)).isoformat(),
        }))  # fmt: skip


def _row(html, label):
    match = re.search(rf"<th scope=\"row\">{label}</th>\s*<td[^>]*>(.*?)</td>", html, re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()


def test_about_says_how_fresh_the_dbs_are(client, app, tmp_path):
    _dbs(app, tmp_path)
    html = client.get("/about").text
    assert _row(html, "Vulnerability DB") == "built 3 h ago, downloaded 1 h ago"
    assert _row(html, "Java DB") == "built 3 h ago, downloaded 1 h ago"


def test_an_outdated_db_says_the_next_scan_updates_it(client, app, tmp_path):
    _dbs(app, tmp_path, updated_h=30, next_h=-6)
    html = client.get("/about").text
    assert _row(html, "Vulnerability DB") == (
        "built 30 h ago, downloaded 1 h ago · a newer one is out: the next scan downloads it"
    )


def test_missing_dbs_say_the_first_scan_downloads_them(client, app, tmp_path):
    _dbs(app, tmp_path, java=False)
    html = client.get("/about").text
    assert _row(html, "Java DB") == "not downloaded: a scan of library packages downloads it"
    app.state.settings = app.state.settings.model_copy(update={"cache_dir": tmp_path / "empty"})
    html = client.get("/about").text
    assert _row(html, "Vulnerability DB") == "not downloaded: the first scan downloads it"


def test_about_names_the_newest_scan_of_the_shown_context(client, seed, app, tmp_path):
    _dbs(app, tmp_path)
    assert _row(client.get("/about").text, "Newest scan of my-cluster") == "none yet"
    run_id = seed.repo.start_run(seed.context, "ui", TRIVY_VERSION, scan_level="library,os", scope="{}")
    seed.repo.finish_run(run_id, "ok")
    seed.clock.now += timedelta(hours=5)
    assert _row(client.get("/about").text, "Newest scan of my-cluster") == "Run 1, 5 h ago"


def test_about_names_what_runs_and_the_project(client, app, tmp_path):
    _dbs(app, tmp_path)
    html = client.get("/about").text
    assert _row(html, "kubedelos") == kubedelos.__version__
    assert _row(html, "Trivy") == f"v{TRIVY_VERSION} (pinned, checksum-verified)"
    assert _row(html, "License") == "Apache-2.0"
    for url in (
        "https://github.com/k8s-servant/kubedelos",
        "https://github.com/k8s-servant/kubedelos/issues",
        "https://github.com/k8s-servant/kubedelos/blob/main/CHANGELOG.md",
        "https://github.com/k8s-servant/kubedelos/security/policy",
    ):
        assert f'href="{url}"' in html
    assert ">Security policy (report a vulnerability privately)</a>" in html
    assert "never changes the cluster" in html and "never reads Secrets" in html


def test_about_names_a_custom_trivy(client, app, tmp_path):
    _dbs(app, tmp_path)
    app.state.settings = app.state.settings.model_copy(update={"trivy_path": tmp_path / "my-trivy"})
    assert _row(client.get("/about").text, "Trivy") == f"custom: {tmp_path / 'my-trivy'}"


def test_nav_ends_with_about(client, app, tmp_path):
    _dbs(app, tmp_path)
    nav = client.get("/about").text.split('<nav aria-label="Main">', 1)[1].split("</nav>", 1)[0]
    assert re.findall(r">([A-Z][a-z]+)</a>", nav)[-2:] == ["Settings", "About"]
    assert '<a href="/about" aria-current="page">About</a>' in nav
