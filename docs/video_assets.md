# Video assets: mdxss-guard

Three concrete commands for a short demo video. `docs/demo_chat.html` and `docs/demo_clean.html` are self-contained pages built by `scripts/build_demo.py`.

## Beat sheet (outputs are captured from real runs)

| time | beat | command | captured output (first line) |
| --- | --- | --- | --- |
| 0:00-0:20 | Hook: the model's Markdown answer executes JavaScript | `python -m mdxss_guard scan examples/poisoned_render.md` | mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars) |
| 0:20-0:55 | Scan the poisoned answer | `python -m mdxss_guard scan examples/poisoned_render.md` | mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars) |
| 0:55-1:25 | The CI gate blocks it | `python -m mdxss_guard scan examples/poisoned_render.md --fail-on high` | mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars) |
| 1:25-2:00 | Clean without losing the answer or the code block | `python -m mdxss_guard clean examples/poisoned_render.md -o evidence/raw/cleaned_render.md` | wrote evidence/raw/cleaned_render.md (mode=strip, findings before=7, after=0) |
| 2:00-2:20 | Re-scan the cleaned answer with the strictest gate | `python -m mdxss_guard scan evidence/raw/cleaned_render.md --fail-on low` | mdxss-guard 0.1.0  scan  evidence/raw/cleaned_render.md  (24 lines, 564 chars) |
| 2:20-2:35 | Tests prove the false-positive behaviour | python -m unittest discover -s tests -t . | Ran 38 tests in ... OK |
| 2:35-2:50 | Honest limits | see docs/THREAT_MODEL.md | heuristic, renderer-dependent, mutation-XSS out of scope |

## Real command transcripts for the recording

### 0:00-0:20 -- Hook: the model's Markdown answer executes JavaScript

Open `docs/demo_chat.html` first: the harmless onerror payload fires and the alert panel turns red.

```console
$ python -m mdxss_guard scan examples/poisoned_render.md
mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars)
HIGH   MDX-EVENT-HANDLER    line 5    col 1    Inline event handler attribute 'onerror' on <img>
HIGH   MDX-SCRIPT           line 7    col 1    Inline <script> element in rendered Markdown executes JavaScript
HIGH   MDX-JS-URL           line 9    col 32   Markdown link destination uses a javascript: URL
HIGH   MDX-JS-URL           line 11   col 1    href attribute uses a javascript:/vbscript: URL
HIGH   MDX-FRAME            line 13   col 1    <iframe> is an active content container
HIGH   MDX-EVENT-HANDLER    line 15   col 1    Inline event handler attribute 'onload' on <svg>
HIGH   MDX-SVG              line 15   col 1    <svg> can carry active content (script, onload)
summary: 7 finding(s): 7 high, 0 medium, 0 low
[exit code: 0]
```

### 0:20-0:55 -- Scan the poisoned answer

Show the seven high findings (script, onerror, javascript: URLs, iframe, svg).

```console
$ python -m mdxss_guard scan examples/poisoned_render.md
mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars)
HIGH   MDX-EVENT-HANDLER    line 5    col 1    Inline event handler attribute 'onerror' on <img>
HIGH   MDX-SCRIPT           line 7    col 1    Inline <script> element in rendered Markdown executes JavaScript
HIGH   MDX-JS-URL           line 9    col 32   Markdown link destination uses a javascript: URL
HIGH   MDX-JS-URL           line 11   col 1    href attribute uses a javascript:/vbscript: URL
HIGH   MDX-FRAME            line 13   col 1    <iframe> is an active content container
HIGH   MDX-EVENT-HANDLER    line 15   col 1    Inline event handler attribute 'onload' on <svg>
HIGH   MDX-SVG              line 15   col 1    <svg> can carry active content (script, onload)
summary: 7 finding(s): 7 high, 0 medium, 0 low
[exit code: 0]
```

### 0:55-1:25 -- The CI gate blocks it

`--fail-on high` returns exit code 1, ready for a pipeline gate.

```console
$ python -m mdxss_guard scan examples/poisoned_render.md --fail-on high
mdxss-guard 0.1.0  scan  examples/poisoned_render.md  (24 lines, 1080 chars)
HIGH   MDX-EVENT-HANDLER    line 5    col 1    Inline event handler attribute 'onerror' on <img>
HIGH   MDX-SCRIPT           line 7    col 1    Inline <script> element in rendered Markdown executes JavaScript
HIGH   MDX-JS-URL           line 9    col 32   Markdown link destination uses a javascript: URL
HIGH   MDX-JS-URL           line 11   col 1    href attribute uses a javascript:/vbscript: URL
HIGH   MDX-FRAME            line 13   col 1    <iframe> is an active content container
HIGH   MDX-EVENT-HANDLER    line 15   col 1    Inline event handler attribute 'onload' on <svg>
HIGH   MDX-SVG              line 15   col 1    <svg> can carry active content (script, onload)
summary: 7 finding(s): 7 high, 0 medium, 0 low
FAIL: 7 finding(s) at or above severity 'high'
[exit code: 1]
```

### 1:25-2:00 -- Clean without losing the answer or the code block

Then rescan: zero findings. The fenced `example` code block is untouched.

```console
$ python -m mdxss_guard clean examples/poisoned_render.md -o evidence/raw/cleaned_render.md
wrote evidence/raw/cleaned_render.md (mode=strip, findings before=7, after=0)
[exit code: 0]
```

### 2:00-2:20 -- Re-scan the cleaned answer with the strictest gate

Exit code 0 with `--fail-on low`.

```console
$ python -m mdxss_guard scan evidence/raw/cleaned_render.md --fail-on low
mdxss-guard 0.1.0  scan  evidence/raw/cleaned_render.md  (24 lines, 564 chars)
summary: 0 finding(s): 0 high, 0 medium, 0 low
PASS: no finding at or above severity 'low'
[exit code: 0]
```

### 2:20-2:35 -- Tests prove the false-positive behaviour

```console
$ python -m unittest discover -s tests -t .
Ran 38 tests
OK
```

### 2:35-2:50 -- Honest limits

State that this is a defence-in-depth linter, not a browser sandbox and not a new CVE.

## Ready files for the edit

- `docs/screenshots/terminal_browser.txt`
- `docs/screenshots/terminal_clean.txt`
- `docs/screenshots/terminal_clean_input.txt`
- `docs/screenshots/terminal_gate.txt`
- `docs/screenshots/terminal_rescan.txt`
- `docs/screenshots/terminal_scan.txt`
- `docs/screenshots/terminal_tests.txt`
- `docs/demo_chat.html`
- `docs/demo_clean.html`
- `docs/EVIDENCE.md`

## OBS/screen-recording notes

- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.
- Run every command from the repository root so the relative paths match.
- The JSON runs are for the evidence log only and are not needed on camera.

## Caveats to state on camera

The demo payload only writes a marker into the DOM; no cookies or data leave the page. Detection is heuristic and depends on how the consuming UI renders raw HTML. The sanitizer covers the common XSS carriers, not every mutation-XSS gadget in every renderer.
