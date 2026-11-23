"use client";

import { CheckCircle2, Download, FileText, Loader2, Megaphone, Printer, RadioTower } from "lucide-react";
import { useState } from "react";
import { Modal } from "@/components/Modal";
import { useLang } from "@/lib/i18n";
import { P, broadcastWarning, getTakedown, syncTelecom, type Campaign, type TakedownDossier } from "@/lib/police";

type Busy = "sync" | "warn" | "dossier" | null;

function warningFor(c: Campaign) {
  const who = c.impersonated_entity ?? "a UAE government entity";
  return {
    title_en: `Scam alert: fake ${who} website`,
    title_ar: `تحذير: موقع مزيف ينتحل صفة ${c.impersonated_entity ?? "جهة حكومية"}`,
    message_en: `Abu Dhabi Police warns: ${c.defanged_domain} impersonates ${who} and steals card, OTP and UAE PASS details. Do not open it. Report scams to Aman 8002626 or SMS 2828.`,
    message_ar: `تحذّر شرطة أبوظبي: الموقع ${c.defanged_domain} ينتحل صفة ${c.impersonated_entity ?? "جهة حكومية"} ويسرق بيانات البطاقات ورموز التحقق وUAE PASS. لا تفتحه. أبلغ عن الاحتيال على أمان 8002626 أو برسالة إلى 2828.`,
    domain: c.domain,
  };
}

export function ActionCenter({ campaign, onChanged }: { campaign: Campaign | null; onChanged: () => void }) {
  const { lang } = useLang();
  const L = (k: keyof typeof P) => P[k][lang];
  const [busy, setBusy] = useState<Busy>(null);
  const [done, setDone] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);
  const [dossier, setDossier] = useState<TakedownDossier | null>(null);

  if (!campaign) {
    return <p className="rounded-2xl bg-white/5 p-4 text-sm text-white/60 ring-1 ring-white/10">{L("selectCampaign")}</p>;
  }
  const c = campaign;
  const key = (what: string) => `${what}:${c.campaign_id}`;

  const run = async (what: Exclude<Busy, null>, fn: () => Promise<string | void>) => {
    setBusy(what);
    setErr(null);
    try {
      const note = await fn();
      if (note) setDone((d) => ({ ...d, [key(what)]: note }));
      onChanged();
    } catch (e) {
      setErr(`${L("failed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  const synced = c.status === "SYNCED_TO_TELECOM_DNS" || Boolean(done[key("sync")]);

  return (
    <div className="space-y-3">
      <div className="rounded-2xl bg-white/5 p-3 ring-1 ring-white/10">
        <p className="font-mono text-sm font-bold text-white" dir="ltr">{c.defanged_domain}</p>
        <p className="mt-0.5 text-xs text-white/60">
          {c.impersonated_entity ?? "—"} · <span dir="ltr">{c.campaign_id}</span>
        </p>
      </div>

      <button
        type="button"
        disabled={busy !== null || synced}
        onClick={() => run("sync", async () => (await syncTelecom(c.campaign_id, c.domain)).rpz_record)}
        className="flex w-full items-center justify-between gap-3 rounded-2xl bg-sky-600 px-4 py-3 text-start text-sm font-bold text-white shadow transition hover:bg-sky-500 disabled:cursor-default disabled:opacity-90"
      >
        <span className="flex items-center gap-2">
          {busy === "sync" ? <Loader2 className="size-4 animate-spin" /> : <RadioTower className="size-4" />}
          {L("syncTelecom")}
        </span>
        {synced && (
          <span className="flex items-center gap-1 rounded-full bg-emerald-500 px-2 py-0.5 text-[11px]">
            <CheckCircle2 className="size-3.5" /> {L("synced")}
          </span>
        )}
      </button>
      {synced && (
        <p className="rounded-xl bg-emerald-500/10 px-3 py-2 font-mono text-[11px] text-emerald-300 ring-1 ring-emerald-400/25" dir="ltr">
          RPZ · {done[key("sync")] ?? `${c.domain} CNAME .`} · rpz.saqr-intel.ae
        </p>
      )}

      <button
        type="button"
        disabled={busy !== null}
        onClick={() => run("warn", async () => (await broadcastWarning(warningFor(c))).warning.id)}
        className="flex w-full items-center justify-between gap-3 rounded-2xl bg-crimson-600 px-4 py-3 text-start text-sm font-bold text-white shadow transition hover:bg-crimson-700 disabled:opacity-70"
      >
        <span className="flex items-center gap-2">
          {busy === "warn" ? <Loader2 className="size-4 animate-spin" /> : <Megaphone className="size-4" />}
          {L("broadcast")}
        </span>
        {done[key("warn")] && (
          <span className="flex items-center gap-1 rounded-full bg-white px-2 py-0.5 text-[11px] text-crimson-700">
            <CheckCircle2 className="size-3.5" /> {L("broadcasted")}
          </span>
        )}
      </button>

      <button
        type="button"
        disabled={busy !== null}
        onClick={() =>
          run("dossier", async () => {
            setDossier(await getTakedown(c.campaign_id));
          })
        }
        className="flex w-full items-center gap-2 rounded-2xl bg-white px-4 py-3 text-start text-sm font-bold text-navy-900 shadow transition hover:bg-white/90 disabled:opacity-70"
      >
        {busy === "dossier" ? <Loader2 className="size-4 animate-spin" /> : <FileText className="size-4" />}
        {L("dossier")}
      </button>

      {err && <p className="rounded-xl bg-crimson-600/20 px-3 py-2 text-xs text-red-200 ring-1 ring-crimson-600/40">{err}</p>}

      <DossierModal dossier={dossier} onClose={() => setDossier(null)} />
    </div>
  );
}

function DossierModal({ dossier, onClose }: { dossier: TakedownDossier | null; onClose: () => void }) {
  const { lang } = useLang();
  const L = (k: keyof typeof P) => P[k][lang];
  const d = dossier;

  const downloadJson = () => {
    if (!d) return;
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${d.aman_ref_id}-takedown-dossier.json`;
    a.click();
    window.setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };

  const row = (label: string, value: string | number | null | undefined) => (
    <div className="grid grid-cols-[minmax(0,10rem)_1fr] gap-3 border-b border-line py-1.5 text-sm last:border-0">
      <dt className="font-semibold text-ink-soft">{label}</dt>
      <dd className="break-all font-mono text-ink" dir="ltr">{value ?? "—"}</dd>
    </div>
  );

  return (
    <Modal open={Boolean(d)} onClose={onClose} title={L("dossierTitle")} wide>
      {d && (
        <div className="space-y-4">
          <div className="print-area space-y-4 rounded-2xl bg-surface">
            <div className="flex items-start justify-between gap-4 border-b-4 border-navy-900 pb-3">
              <div>
                <p className="text-xs font-bold uppercase tracking-widest text-ink-soft">{d.issuing_unit}</p>
                <p className="text-xs font-bold text-ink-soft" dir="rtl">{d.issuing_unit_ar}</p>
                <h3 className="mt-1 text-xl font-extrabold text-ink">Takedown Dossier · ملف طلب الإزالة</h3>
              </div>
              <div className="text-end">
                <p className="text-[11px] font-semibold uppercase text-ink-soft">Aman reference</p>
                <p className="font-mono text-base font-extrabold text-crimson-600" dir="ltr">{d.aman_ref_id}</p>
              </div>
            </div>
            <dl>
              {row("Target domain", d.target_domain)}
              {row("Defanged", d.defanged_domain)}
              {row("Impersonated entity", d.impersonated_entity)}
              {row("Risk score", `${d.risk_score} / 100`)}
              {row("IP address", d.all_ip_addresses.join(", ") || d.ip_address)}
              {row("ASN", d.asn)}
              {row("Registrar", d.registrar)}
              {row("Registrar abuse email", d.all_abuse_contacts.join(", ") || d.registrar_abuse_email)}
              {row("SSL certificate age", d.ssl_age)}
              {row("Citizen reports", d.citizen_reports_count)}
              {row("Interception channels", d.channels.join(", "))}
              {row("Campaign status", d.status)}
              {row("Generated", new Date(d.generated_at).toLocaleString("en-GB"))}
            </dl>
            <div>
              <p className="mb-1.5 text-xs font-bold uppercase tracking-wider text-ink-soft">Red flags · علامات الخطر</p>
              <ul className="space-y-1.5 text-sm">
                {d.red_flags.map((f) => (
                  <li key={f.code} className="rounded-xl bg-muted px-3 py-2">
                    <span className="me-2 rounded bg-crimson-600 px-1.5 py-0.5 font-mono text-[10px] font-bold text-white">{f.code}</span>
                    {f.en}
                    <span className="mt-0.5 block text-ink-soft" dir="rtl">{f.ar}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="mb-1.5 text-xs font-bold uppercase tracking-wider text-ink-soft">Requested actions</p>
              <ol className="list-decimal space-y-1 ps-5 text-sm text-ink">
                {d.requested_actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ol>
            </div>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <button type="button" onClick={downloadJson}
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-navy-900 px-4 py-3 text-sm font-bold text-white hover:bg-navy-800 dark:bg-white dark:text-navy-900">
              <Download className="size-4" /> {L("downloadJson")}
            </button>
            <button type="button" onClick={() => window.print()}
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-muted px-4 py-3 text-sm font-bold text-ink ring-1 ring-line hover:bg-line">
              <Printer className="size-4" /> {L("printPdf")}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
