"""Contract tests verifying v2.1.0 hardware-hash guestbook decommission."""

import json
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"


def test_guestbook_artifacts_and_builder_removed():
    assert not (REPO_ROOT / "scripts" / "build_guestbook.py").exists()
    assert not (REPO_ROOT / "dist" / "guestbook.json").exists()
    assert not (REPO_ROOT / "dist" / "guestbook" / "index.html").exists()


def test_v1_hello_returns_410_gone_on_pages_and_worker():
    route_uri = (REPO_ROOT / "functions" / "v1" / "[[route]].js").as_uri()
    worker_uri = (REPO_ROOT / "serverless" / "worker.js").as_uri()
    mw_uri = (REPO_ROOT / "functions" / "_middleware.js").as_uri()

    script = f"""
      const routeMod = await import({json.dumps(route_uri)});
      const workerMod = await import({json.dumps(worker_uri)});
      const mwMod = await import({json.dumps(mw_uri)});

      let dbCalls = 0;
      const env = {{
        DB: {{
          prepare() {{
            dbCalls += 1;
            return {{ bind() {{ return {{ run: async () => ({{}}) }}; }} }};
          }}
        }}
      }};

      const pagesPost = await routeMod.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/v1/hello', {{ method: 'POST', body: '{{}}' }}),
        env,
      }});
      const pagesGet = await routeMod.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/v1/hello', {{ method: 'GET' }}),
        env,
      }});
      const workerPost = await workerMod.default.fetch(
        new Request('https://fmagenticl-registry.pages.dev/v1/hello', {{ method: 'POST', body: '{{}}' }}),
        env
      );

      let nextCalled = 0;
      const mwRes = await mwMod.onRequest({{
        request: new Request('https://fmagenticl-registry.pages.dev/v1/hello', {{ method: 'POST' }}),
        env,
        next: async () => {{
          nextCalled += 1;
          return routeMod.onRequest({{
            request: new Request('https://fmagenticl-registry.pages.dev/v1/hello', {{ method: 'POST', body: '{{}}' }}),
            env,
          }});
        }},
      }});

      process.stdout.write(JSON.stringify({{
        pagesPost: pagesPost.status,
        pagesGet: pagesGet.status,
        workerPost: workerPost.status,
        mwStatus: mwRes.status,
        nextCalled,
        dbCalls,
        pagesBody: await pagesPost.json(),
        workerBody: await workerPost.json(),
      }}));
    """
    res = subprocess.run(
        [NODE, "--input-type=module", "-e", script],
        capture_output=True, text=True, encoding="utf-8", check=True, timeout=30,
    )
    out = json.loads(res.stdout)
    assert out["pagesPost"] == 410
    assert out["pagesGet"] == 410
    assert out["workerPost"] == 410
    assert out["mwStatus"] == 410
    assert out["nextCalled"] == 1
    assert out["dbCalls"] == 0
    assert isinstance(out["pagesBody"], dict) and out["pagesBody"]
    assert isinstance(out["workerBody"], dict) and out["workerBody"]
