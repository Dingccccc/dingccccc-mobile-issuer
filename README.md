# Banana Desktop Mobile Issuer

Static offline-capable PWA for issuing Banana Desktop activation codes on an
iPhone. Deploy it manually through the `Deploy mobile issuer` GitHub Actions
workflow, then open the HTTPS Pages address in Safari and add it to the Home
Screen.

This repository intentionally contains no production private key, encrypted
mobile key, customer license, activation code, or issuance ledger. Import a
password-encrypted `.bdkey` only into your own iPhone after the page is live.
