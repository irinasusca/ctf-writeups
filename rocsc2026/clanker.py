import re
import asyncio
import itertools
import numpy as np
from PIL import Image
import io
from playwright.async_api import async_playwright

BASE = "http://34.185.144.221:31082"
NUM_WORKERS = 10

DIGIT_MAP = {}
map_lock = asyncio.Lock()
input_lock = asyncio.Lock()
flag_found = asyncio.Event()

# Each worker gets its own counter in a completely separate range
# Worker 1: 11000100, 11000101, ...
# Worker 2: 22000200, 22000201, ...
# etc.
def make_counter(worker_id):
    return itertools.count(worker_id * 11000100)

def check_flag(text):
    for pattern in [r'ctf\{.*?\}', r'ROCSC\{.*?\}', r'CTF\{.*?\}', r'FLAG\{.*?\}']:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group()
    return None

def extract_segments(screenshot_bytes):
    img = Image.open(io.BytesIO(screenshot_bytes)).convert('L')
    inner = img.crop((3, 3, img.width-3, img.height-3))
    arr = np.array(inner) < 50
    rows = np.any(arr, axis=1)
    cols = np.any(arr, axis=0)
    if not rows.any():
        return [], None
    rmin, rmax = np.where(rows)[0][[0, -1]]
    cmin, cmax = np.where(cols)[0][[0, -1]]
    cropped = arr[max(0,rmin-2):rmax+2, max(0,cmin-2):cmax+2]
    col_proj = np.sum(cropped, axis=0)
    in_char = False
    segments = []
    start = 0
    for x in range(len(col_proj)):
        if not in_char and col_proj[x] > 0:
            in_char = True; start = x
        elif in_char and col_proj[x] == 0:
            in_char = False; segments.append([start, x])
    if in_char:
        segments.append([start, len(col_proj)])
    if not segments:
        return [], None
    # Captcha is always exactly 5 chars: D D + D D
    # Merge closest pairs until we have exactly 5
    while len(segments) > 5:
        gaps = [segments[i+1][0] - segments[i][1] for i in range(len(segments)-1)]
        min_idx = gaps.index(min(gaps))
        segments[min_idx][1] = segments[min_idx+1][1]
        segments.pop(min_idx+1)
    return [cropped[:, x1:x2] for x1, x2 in segments], cropped

def seg_to_hash(seg):
    img = Image.fromarray(seg.astype(np.uint8) * 255)
    img = img.resize((17, 26), Image.NEAREST)
    return tuple(np.array(img).flatten() > 128)

def decode_captcha(screenshot_bytes):
    segs, _ = extract_segments(screenshot_bytes)
    if not segs:
        return None, []
    result = ''
    unknowns = []
    for i, seg in enumerate(segs):
        # Position 2 (middle of 5) is always the + sign
        if i == 2:
            result += '+'
            continue
        h = seg_to_hash(seg)
        if h in DIGIT_MAP:
            result += DIGIT_MAP[h]
        else:
            result += '?'
            unknowns.append((i, seg, h))
    return result, unknowns

def seed_from_known_captcha():
    try:
        with open('captcha_test.png', 'rb') as f:
            data = f.read()
        segs, _ = extract_segments(data)
        known = ['0', '9', '+', '9', '2']
        if len(segs) == len(known):
            for seg, label in zip(segs, known):
                DIGIT_MAP[seg_to_hash(seg)] = label
            print(f"[+] Seeded map: {set(known)} ({len(DIGIT_MAP)} entries)")
        else:
            print(f"[-] Seed failed: expected 5 segs, got {len(segs)}")
    except FileNotFoundError:
        print("[-] captcha_test.png not found, will learn interactively")

async def learn_unknown(seg, h, worker_id):
    async with input_lock:
        if h in DIGIT_MAP:
            return DIGIT_MAP[h]
        print(f"\n[W{worker_id}] Unknown character:")
        for row in seg:
            print('    ' + ''.join('██' if p else '  ' for p in row))
        print(f"    What digit/char is this? ", end='', flush=True)
        label = await asyncio.get_event_loop().run_in_executor(None, input)
        label = label.strip()
        if label:
            DIGIT_MAP[h] = label
            print(f"    [+] Learned '{label}' (map: {len(DIGIT_MAP)} entries)")
        return label

def get_bet(coins):
    if coins >= 100:
        return max(1, 200 - coins)  # one win reaches 200
    return max(1, coins // 2)       # bet half, fast growth

async def worker(worker_id, browser):
    counter = make_counter(worker_id)

    async def new_session():
        idx = next(counter)
        context = await browser.new_context()
        page = await context.new_page()
        await page.goto(f"{BASE}/register")
        await page.fill('input[name="username"]', str(idx))
        await page.fill('input[name="password"]', str(idx))
        await page.click('button[type="submit"]')
        print(f"[W{worker_id}] New account: {idx}")
        return context, page

    context, page = await new_session()

    while not flag_found.is_set():
        await page.goto(f"{BASE}/game")
        html = await page.content()
        flag = check_flag(html)
        if flag:
            print(f"\n[W{worker_id}] 🚩 FLAG: {flag}")
            flag_found.set()
            break

        hud_text = await page.inner_text('.hud')
        m = re.search(r'COINS: (\d+)', hud_text)
        if not m:
            continue
        coins = int(m.group(1))

        if coins == 0:
            print(f"[W{worker_id}] Busted!")
            await context.close()
            context, page = await new_session()
            continue

        element = await page.query_selector('.captcha-container')
        screenshot_bytes = await element.screenshot()
        decoded, unknowns = decode_captcha(screenshot_bytes)

        if unknowns:
            for uidx, seg, h in unknowns:
                if h in DIGIT_MAP:
                    continue
                label = await learn_unknown(seg, h, worker_id)
                if not label:
                    break
            decoded, unknowns = decode_captcha(screenshot_bytes)

        if not decoded or '?' in decoded:
            continue

        match = re.search(r'(\d+)\+(\d+)', decoded)
        if not match:
            continue

        solution = int(match.group(1)) + int(match.group(2))
        bet = get_bet(coins)
        print(f"[W{worker_id}] Coins:{coins} | {decoded}={solution} | bet:{bet} | map:{len(DIGIT_MAP)}")

        await page.fill('input[name="bet"]', str(bet))
        await page.fill('input[name="captcha_answer"]', str(solution))
        await page.click('button[type="submit"]')

        html = await page.content()
        flag = check_flag(html)
        if flag:
            print(f"\n[W{worker_id}] 🚩 FLAG: {flag}")
            flag_found.set()
            break

        try:
            flash = (await page.inner_text('.flash')).strip()
            print(f"[W{worker_id}]   => {flash}")
        except:
            pass

    await context.close()

async def main():
    seed_from_known_captcha()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        print(f"[+] Launching {NUM_WORKERS} workers...")
        tasks = [asyncio.create_task(worker(i+1, browser)) for i in range(NUM_WORKERS)]
        await flag_found.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await browser.close()

asyncio.run(main())
