# SAQR-INTEL phone-demo scam page

A **training replica** of the fake TAMM page (`/mock-scam/tamm-fine`) on its own address,
<https://saqr-demo-scam.vercel.app>, so the phone DNS shield can block it without blocking SAQR
itself. The form has no action and its button does nothing; the banner says it is not a real site.

Demo: scan the link on the citizen site once (HIGH-RISK) → SAQR adds it to NextDNS within seconds →
on a shielded phone it no longer opens ("Safari can't open the page") and the phone gets a SAQR
alert. A laptop without the shield still opens it.

Redeploy (from this folder): `npx vercel@latest deploy --prod --yes`
