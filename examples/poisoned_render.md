# Release notes (model-generated answer)

Here is the changelog summary you asked for. The `deploy.sh` script was updated and the API is stable.

<img src=x onerror="document.getElementById('xss-alert').textContent='XSS-EXECUTED-7C1A: onerror handler ran';document.getElementById('xss-alert').classList.add('fired')">

<script>document.getElementById('xss-alert').textContent='XSS-EXECUTED-7C1A: script tag ran';document.getElementById('xss-alert').classList.add('fired');</script>

[Click here for the full report](javascript:alert(document.cookie))

<a href="javascript:alert(1)">Raw HTML link</a>

<iframe src="https://attacker.example/frame"></iframe>

<svg onload="document.getElementById('xss-alert').textContent='XSS-EXECUTED-7C1A: svg onload ran';document.getElementById('xss-alert').classList.add('fired')"></svg>

A benign inline element like **bold** and a [safe link](https://example.com/docs) is fine.

The protected snippet below must never be touched by the sanitizer:

```html
<script>console.log("legit example in docs")</script>
<img src=x onerror=alert(1)>
```
