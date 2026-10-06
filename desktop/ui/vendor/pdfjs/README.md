# PDF.js

Mozilla's PDF.js, which draws the PDF in the app's report preview. Copied
unchanged from the npm package `pdfjs-dist` 6.4.299, its `legacy/build`
(the build for older web engines, since the app runs in whatever WebView
the system has: WebView2 on Windows, WKWebView on macOS, WebKitGTK on
Linux):

- `pdf.min.mjs`, the library
- `pdf.worker.min.mjs`, its worker
- `LICENSE`, Apache License 2.0

To update, replace the two files with the same two from a newer
`pdfjs-dist`, change the version above, and open a report preview's PDF tab.
