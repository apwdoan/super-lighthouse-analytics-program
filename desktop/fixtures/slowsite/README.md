# Slow-site fixture

A deliberately awful page, served offline by `tests/fixture_server.py`.

It exists because a *clean* page cannot test the Lighthouse extractor: every
opportunity reports zero savings, so a broken extractor looks identical to a
working one. Lighthouse 13 renamed every opportunity audit and moved the
savings API, which is exactly the kind of change that fails silently.

What each piece is for:

| File | Triggers |
|---|---|
| `index.html` | render-blocking head, 3600-element DOM, oversized image, `@font-face` with no `font-display` |
| `styles.css` | 1500 mostly-unused rules, unminified with comments |
| `app.js` | unminified, legacy transpilation patterns, main-thread work |
| `hero.png` | photo-shaped PNG served at 2x its display size |

The server adds `Cache-Control: no-store`, no compression, and an insecure
cookie.

`slow-lhr.json.gz` in the parent directory is real Lighthouse 13.4.1 output
recorded against this page. Regenerate both together if you change anything
here, or the recorded run stops matching the fixture:

    python -m tests.fixture_server 8899
    # then run a Lighthouse job against http://127.0.0.1:8899/index.html
