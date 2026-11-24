"use client";

import { Check, Copy, Download, FileArchive, Printer } from "lucide-react";
import { useState, type ReactNode } from "react";
import { screenshotUrl, evidencePackUrl, type DetectionContext, type DossierFlag, type EvidenceDossier } from "@/lib/police";
import { SOURCE_STYLE, defangUrl, fmtHours, verdictLabel, type L, type Lang } from "./ui";

const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-crimson-600 text-white",
  high: "bg-crimson-600/85 text-white",
  medium: "bg-amber-500 text-navy-900",
  low: "bg-navy-700 text-white",
  info: "bg-navy-700 text-white",
};

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="break-inside-avoid">
      <h4 className="mb-1.5 text-xs font-bold uppercase tracking-wider text-ink-soft">{title}</h4>
      {children}
    </section>
  );
}

export function Rows({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="rounded-xl bg-muted/50 px-3 ring-1 ring-line">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[minmax(0,9.5rem)_1fr] gap-3 border-b border-line py-1.5 text-sm last:border-0">
          <dt className="font-semibold text-ink-soft">{label}</dt>
          <dd className="break-all font-mono text-[13px] text-ink" dir="ltr">
            {value === null || value === undefined || value === "" ? "—" : value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Every reason behind the score, highest weight first, in both languages (the reader's first). */
export function ReasonList({ flags, lang, L }: { flags: DossierFlag[]; lang: Lang; L: L }) {
  const sorted = [...flags].sort((a, b) => (b.points ?? 0) - (a.points ?? 0));
  return (
    <ul className="space-y-1.5 text-sm">
      {sorted.map((f, i) => (
        <li key={`${f.code}-${i}`} className="rounded-xl bg-muted px-3 py-2">
          <span className="flex flex-wrap items-center gap-1.5">
            <span className={`rounded px-1.5 py-0.5 font-mono text-[11px] font-bold ${SEVERITY_TONE[f.severity] ?? SEVERITY_TONE.low}`}>{f.code}</span>
            {typeof f.points === "number" && (
              <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-[11px] font-bold text-ink ring-1 ring-line" dir="ltr">
                +{f.points} {L("pts")}
              </span>
            )}
          </span>
          <span className="mt-1 block text-ink" dir={lang === "ar" ? "rtl" : "ltr"}>{lang === "ar" ? f.ar : f.en}</span>
          <span className="mt-0.5 block text-xs text-ink-soft" dir={lang === "ar" ? "ltr" : "rtl"}>{lang === "ar" ? f.en : f.ar}</span>
        </li>
      ))}
    </ul>
  );
}

export function DetectionSummary({ det, L }: { det: DetectionContext; L: L }) {
  const src = SOURCE_STYLE[det.source];
  const visits = det.citizen_visits;
  return (
    <div className="rounded-xl bg-violet-500/10 p-3 ring-1 ring-violet-400/30">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="rounded-full bg-violet-600 px-2 py-0.5 text-[11px] font-extrabold uppercase tracking-wide text-white">
          {src ? L(src.key) : det.source}
        </span>
        {det.simulated && (
          <span className="rounded-full bg-amber-400 px-2 py-0.5 text-[11px] font-black tracking-widest text-navy-900">{L("simulated")}</span>
        )}
        <span className="text-xs text-ink-soft">{det.source_label}</span>
      </div>
      <Rows
        rows={[
          [L("firstSeen"), det.first_seen],
          [L("domainAge"), fmtHours(det.domain_age_hours, L)],
          [L("citizensMet"), visits === 0 ? L("noCitizenYet") : `${visits} · ${det.citizen_visits_blocked}/${visits} ${L("blockedOf")}`],
          [L("leadTime"), det.lead_time_hours === null ? "—" : fmtHours(det.lead_time_hours, L)],
        ]}
      />
      {det.simulated && <p className="mt-2 text-xs text-ink-soft">{L("simulatedHint")}</p>}
    </div>
  );
}

function noShot(note: string | null | undefined, L: L): string {
  if (!note) return L("noShotFailed");
  if (note.includes("cloud mode")) return L("noShotCloud");
  if (note.includes("fast scan")) return L("noShotFast");
  if (note.includes("not available")) return L("noShotUnavailable");
  return L("noShotFailed");
}

function CopyBlock({ title, text, L }: { title: string; text: string; L: L }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="break-inside-avoid">
      <div className="mb-1 flex items-center justify-between gap-2">
        <p className="text-xs font-semibold text-ink-soft">{title}</p>
        <button type="button" onClick={() => void copy()}
          className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-[11px] font-bold text-ink ring-1 ring-line hover:bg-line print:hidden">
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? L("copied") : L("copy")}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-xl bg-navy-950 p-3 font-mono text-[11px] leading-relaxed text-emerald-100 print:max-h-none" dir="ltr">
        {text}
      </pre>
    </div>
  );
}

/** The full evidence dossier of one flagged scan (saqr/intel/takedown.build_dossier). */
export function EvidenceView({ ev, lang, L }: { ev: EvidenceDossier; lang: Lang; L: L }) {
  const s = ev.summary;
  const w = ev.whois;
  const n = ev.network;
  const t = ev.tls;
  const sb = ev.sandbox_evidence;
  const hops = sb.redirect_chain ?? [];
  const hashes = Object.entries(ev.evidence_integrity ?? {}).filter(([k]) => k !== "note" && k !== "hash_algorithm");
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-2xl bg-muted p-3 ring-1 ring-line">
        <span className={`grid size-14 shrink-0 place-items-center rounded-2xl text-2xl font-black tabular-nums ${s.risk_score >= 65 ? "bg-crimson-600 text-white" : "bg-amber-500 text-navy-900"}`} dir="ltr">
          {s.risk_score}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-bold uppercase tracking-wider text-ink-soft">{L("riskScore")} · {verdictLabel(s.verdict, L)}</p>
          <p className="truncate font-mono text-base font-extrabold text-ink" dir="ltr">{s.target_defanged}</p>
          <p className="text-xs text-ink-soft">{L("impersonated")}: {s.impersonated_entity ?? "—"}</p>
        </div>
        <div className="text-end">
          <p className="text-[11px] font-semibold uppercase text-ink-soft">{L("caseRef")}</p>
          <p className="font-mono text-sm font-extrabold text-crimson-600" dir="ltr">{ev.case_reference}</p>
          <p className="font-mono text-[11px] text-ink-soft" dir="ltr">{ev.dossier_id} · {ev.scan_id}</p>
        </div>
      </div>

      {ev.detection && (
        <Section title={L("detectionBlock")}>
          <DetectionSummary det={ev.detection} L={L} />
        </Section>
      )}

      <Section title={L("reasons")}>
        <ReasonList flags={ev.red_flags} lang={lang} L={L} />
      </Section>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title={L("whois")}>
          <Rows
            rows={[
              [L("registrar"), w.registrar],
              [L("registered"), w.creation_date],
              [L("domainAge"), fmtHours(w.domain_age_hours, L)],
              [L("registrantCountry"), w.registrant_country],
              [L("abuseContacts"), w.abuse_contacts?.join(", ")],
              [L("nameServers"), w.name_servers?.join(", ")],
            ]}
          />
        </Section>
        <Section title={L("hostingTitle")}>
          <Rows
            rows={[
              [L("ipAddresses"), n.ip_addresses?.join(", ")],
              [L("asn"), [n.asn, n.asn_org].filter(Boolean).join(" · ")],
              [L("country"), n.country],
              ["IPv6", ev.dns?.aaaa?.join(", ")],
              [L("mx"), ev.dns?.mx?.join(", ")],
            ]}
          />
        </Section>
      </div>

      <Section title={L("tls")}>
        <Rows
          rows={[
            [L("issuer"), t.issuer],
            [L("issued"), t.not_before],
            [L("certAge"), fmtHours(t.cert_age_hours, L)],
            [L("fingerprint"), t.sha256],
          ]}
        />
      </Section>

      <Section title={L("redirectChain")}>
        {hops.length <= 1 ? (
          <p className="rounded-xl bg-muted/50 px-3 py-2 text-sm text-ink-soft ring-1 ring-line">{L("noRedirects")}</p>
        ) : (
          <ol className="space-y-1.5" dir="ltr">
            {hops.map((h, i) => (
              <li key={`${h.url}-${i}`} className="flex flex-wrap items-center gap-2 rounded-xl bg-muted/50 px-3 py-2 text-xs ring-1 ring-line">
                <span className="grid size-5 shrink-0 place-items-center rounded-full bg-navy-900 text-[11px] font-black text-white">{i + 1}</span>
                <span className="min-w-0 flex-1 break-all font-mono text-ink">{defangUrl(h.url)}</span>
                {h.status !== null && <span className="rounded bg-surface px-1.5 py-0.5 font-mono font-bold text-ink ring-1 ring-line">HTTP {h.status}</span>}
                {h.via && <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-ink-soft ring-1 ring-line">{h.via}</span>}
                {h.risk && <span className="rounded bg-crimson-600 px-1.5 py-0.5 font-mono font-bold text-white">{h.risk}</span>}
                {h.note && <span className="w-full text-ink-soft">{h.note}</span>}
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section title={L("screenshot")}>
        {sb.screenshot_available ? (
          <div className="overflow-hidden rounded-xl ring-1 ring-line">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={screenshotUrl(ev.scan_id)} alt={`Sandbox screenshot of ${s.target_defanged}`} className="max-h-96 w-full object-cover object-top" />
          </div>
        ) : (
          <p className="rounded-xl bg-muted/50 px-3 py-2 text-sm text-ink-soft ring-1 ring-line">{noShot(sb.screenshot_note, L)}</p>
        )}
      </Section>

      <div className="grid gap-4 md:grid-cols-2">
        <Section title={L("timestamps")}>
          <Rows
            rows={[
              [L("firstSeen"), ev.timestamps?.first_seen],
              [L("scannedAt"), ev.timestamps?.scanned_at],
              [L("generatedAt"), ev.timestamps?.generated_at ?? ev.generated_at],
            ]}
          />
        </Section>
        <Section title={L("hashes")}>
          <Rows rows={hashes.map(([k, v]) => [k.replace(/_sha256$/, ""), v] as [string, ReactNode])} />
        </Section>
      </div>

      <Section title={L("timeline")}>
        <ol className="space-y-1 border-s-2 border-line ps-3 text-xs">
          {ev.timeline.map((e, i) => (
            <li key={`${e.ts}-${i}`}>
              <span className="font-mono text-ink-soft" dir="ltr">{e.ts}</span> · <span className="text-ink">{e.event}</span>{" "}
              <span className="text-ink-soft">({e.source})</span>
            </li>
          ))}
        </ol>
      </Section>

      <Section title={L("notices")}>
        <div className="space-y-3">
          <CopyBlock title={L("registrarNotice")} text={ev.notices.registrar_abuse} L={L} />
          <CopyBlock title={L("hostingNotice")} text={ev.notices.hosting_abuse} L={L} />
        </div>
      </Section>
    </div>
  );
}

/** Download JSON · Print / Save PDF · evidence pack (.zip, built by the backend). */
export function DossierActions({ data, fileName, dossierId, L }: { data: unknown; fileName: string; dossierId?: string | null; L: L }) {
  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fileName;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  return (
    <div className={`grid gap-2 ${dossierId ? "sm:grid-cols-3" : "sm:grid-cols-2"}`}>
      <button type="button" onClick={downloadJson}
        className="inline-flex items-center justify-center gap-2 rounded-2xl bg-navy-900 px-4 py-3 text-sm font-bold text-white hover:bg-navy-800 dark:bg-white dark:text-navy-900">
        <Download className="size-4" /> {L("downloadJson")}
      </button>
      <button type="button" onClick={() => window.print()}
        className="inline-flex items-center justify-center gap-2 rounded-2xl bg-muted px-4 py-3 text-sm font-bold text-ink ring-1 ring-line hover:bg-line">
        <Printer className="size-4" /> {L("printPdf")}
      </button>
      {dossierId && (
        <a href={evidencePackUrl(dossierId)} download
          className="inline-flex items-center justify-center gap-2 rounded-2xl bg-crimson-600 px-4 py-3 text-sm font-bold text-white hover:bg-crimson-700">
          <FileArchive className="size-4" /> {L("downloadZip")}
        </a>
      )}
    </div>
  );
}
