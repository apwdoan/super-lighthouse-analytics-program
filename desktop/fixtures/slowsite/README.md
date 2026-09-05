# Slow-site fixture

A deliberately awful page, served by any static server.

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

The recording server adds `Cache-Control: no-store`, no compression, and
an insecure cookie, so the recorded LHR carries those findings.

`slow-lhr.json.gz` in the parent directory is real Lighthouse 13.4.1 output
recorded against this page. Regenerate both together if you change anything
here, or the recorded run stops matching the fixture: serve this directory
with any static server that reproduces those headers, and run a Lighthouse
job against it.
