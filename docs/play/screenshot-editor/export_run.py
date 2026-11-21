import re, time
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(accept_downloads=True, viewport={"width": 1280, "height": 860}, device_scale_factor=2)
    pg = ctx.new_page()
    pg.goto("http://localhost:3000", wait_until="networkidle")
    pg.wait_for_selector('button[title^="Export every size"]', timeout=15000)
    with pg.expect_download(timeout=120000) as dl:
        pg.click('button[title^="Export every size"]')
    d = dl.value
    path = "/tmp/opencode/fg-shots-editor/proof/export.zip"
    d.save_as(path)
    print("SAVED", d.suggested_filename, path)
    b.close()
