import time
import os
import json
import re

from playwright.sync_api import sync_playwright
# from playwright_stealth import stealth_sync
import cbor2

version = os.environ.get('TARGET_APP_VERSION')

USER_DATA_DIR = '/home/appuser/.config/google-chrome'
EXECUTABLE_PATH = '/usr/bin/google-chrome-stable'
base_url = "https://decrypt.day/app/id1489932710"

def cbor_to_list(b: bytes):
    hex_str = b.hex()
    return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]

with sync_playwright() as p:
    print("[-] Setup Chrome")
    
    # pr launch_persistent_context
    browser = p.chromium.launch(
        #user_data_dir=USER_DATA_DIR,
        executable_path=EXECUTABLE_PATH,
        headless=False,
        args=[
            '--no-sandbox',
            '--disable-gpu',
            '--disable-blink-features=AutomationControlled', 
            '--start-maximized',
            # '--no-first-run',
            # '--no-default-browser-check',
            # '--disable-dev-shm-usage',
        ],
        ignore_default_args=["--enable-automation"],
    )
    
    print("Setup context")
    context = browser.new_context()
    context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
    """)

    print("[-] Open app info page")
    page = context.new_page()
    #stealth_sync(page)
    page.goto(base_url, timeout=60000)

    page.wait_for_load_state("domcontentloaded")
    
    if "Just a moment" in page.title() or "Cloudflare" in page.title() or "cf" in page.url:
        time.sleep(20)
        if "Just a moment" in page.title() or "Cloudflare" in page.title() or "cf" in page.url:
            print("[x] Warning: Cloudflare blocked us. Quit.")
            exit(1)
    
    page.wait_for_load_state("domcontentloaded")


    # fetch download link via JS fetch
    payload = cbor2.dumps({
        "appId": "cl9se40tq00abdofwqtgov0zs",
        "version": version,
        "isPremier": cbor2.undefined,
    })
    payload_text = ",".join(map(str,cbor_to_list(payload)))

    result = page.evaluate("""
        async () => {
            const formData = new FormData();
            formData.append('data', '$PAYLOAD$');

            const resp = await fetch('$BASE_PAGE_URL$?/files', {
                method: 'POST',
                body: formData,
            });
            return await resp.text();
        }
    """
        .replace("$BASE_PAGE_URL$", base_url)
        .replace("$PAYLOAD$", payload_text)
    )
    # print(type(result))
    # print(result)
    assert isinstance(result, str), f"Invalid response type: {type(result)}"

    try:
        download_page_req = json.loads(result)
        assert download_page_req.get("type") == "success", f"Failed when request download path: {download_page_req}"
        dl_page_details: list = json.loads(download_page_req.get("data"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}\nRequest result: {result}")
    
    free_dl_path = ""
    try:
        domain = None
        for obj in dl_page_details[::-1]:
            if not(isinstance(obj, str) and len(obj.split(".")) >= 2):
                continue
            domain = obj
            break

        free_dl_path = dl_page_details[dl_page_details.index(domain) - 3]
        if free_dl_path is None:
            raise ValueError
    except (IndexError, ValueError):
        try:
            # fallback
            print("[!] Fallback: scanning for valid download path...")
            for e in dl_page_details[::-1]:
                if not (isinstance(e, str) and len(e) == 21):
                    continue
                free_dl_path = e
                break
        except:
            print("[!] Unable determine download path")
            print(dl_page_details)
            exit(1)
    
    # goto download page
    if not free_dl_path:
        raise ValueError(f"Cannot get download page path. Request: {download_page_req}")

    download_page_url = f"{base_url}/dl/{free_dl_path}"
    print(f"[-] Download Page: {download_page_url}")

    dl_page = context.new_page()
    #stealth_sync(dl_page)
    dl_page.goto(download_page_url, referer=base_url)

    btn = dl_page.locator("button.btn-download").filter(has_text="Get download link")
    btn.click()

    print("[-] Trying to fetch download link")
    time.sleep(10)

    btn = dl_page.locator("button.btn-download").filter(has_text="Download")
    print("[-] Preparing download")

    with dl_page.expect_download() as download_info:
        btn.click()

    download = download_info.value
    semantic_version = r'\d+\.\d+\.\d+'
    match = re.search(semantic_version, download.suggested_filename)
    if match:
        version = match.group()
        print(f"[-] Version: {version}")
    else:
        version = f"unknown_{download.suggested_filename}"
        print(f"[!] Unable find semantic version: {version}")

    download_path = os.path.join("/home/appuser/Downloads", f"{version}.ipa")
    download.save_as(download_path)
    print(f"[-] File saved at: {download_path}")
    print("[-] Exited")