# TODO

## Email scanning
- [ ] **Email attachment scanning** — today SAQR only looks at an attachment's *name* (dangerous types such as `.exe`, `.html`, double extensions like `invoice.pdf.exe`, hidden right-to-left characters). It does not open the file. To add:
  - scan the attachment's contents: links and QR codes inside PDFs / images ("quishing"), HTML attachments that contain a fake login form, Office files with macros, archives (`.zip`, `.iso`) and what is inside them;
  - send any links found inside attachments through the normal link scan;
  - check file hashes against a malware feed;
  - size limits and safe handling (never run or render an attachment);
  - show the result in the web app verdict screen and the extension banner.
