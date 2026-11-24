"use client";

import { CheckCircle2, FileText, Loader2, Megaphone, RadioTower } from "lucide-react";
import { useState } from "react";
import { Modal } from "@/components/Modal";
import { useLang } from "@/lib/i18n";
import { P, STATUS_LABEL, broadcastWarning, getTakedown, syncTelecom, type Campaign, type TakedownDossier } from "@/lib/police";
import { DossierActions, EvidenceView, ReasonList, Rows } from "./EvidenceDossier";

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
    return <p className="rounded-2xl border border-line bg-canvas p-4 text-sm text-ink-soft">{L("selectCampaign")}</p>;
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
      <div className="border-b border-line pb-3">
        <p className="font-mono text-sm font-bold text-ink" dir="ltr">{c.defanged_domain}</p>
        <p className="mt-0.5 text-xs text-ink-soft">
          {c.impersonated_entity ?? "—"} · <span dir="ltr">{c.campaign_id}</span>
        </p>
      </div>

      <button
        type="button"
        disabled={busy !== null || synced}
        onClick={() => run("sync", async () => (await syncTelecom(c.campaign_id, c.domain)).rpz_record)}
        className="flex w-full items-center justify-between gap-3 press rounded-2xl bg-emerald-700 px-4 py-3 text-start text-sm font-bold text-white transition hover:bg-emerald-800 disabled:cursor-default disabled:opacity-90"
      >
        <span className="flex items-center gap-2">
          {busy === "sync" ? <Loader2 className="size-4 animate-spin" /> : <RadioTower className="size-4" />}
          {L("syncTelecom")}
        </span>
        {synced && (
          <span className="inline-flex -rotate-3 items-center gap-1 rounded-md border-2 border-white/90 px-2 py-1 text-[11px] leading-none font-extrabold uppercase tracking-[0.1em]">
            <CheckCircle2 className="size-3.5" /> {L("synced")}
          </span>
        )}
      </button>
      {synced && (
        <p className="rounded-xl border border-emerald-600/30 bg-emerald-600/10 px-3 py-2 font-mono text-xs text-emerald-800 dark:text-emerald-300" dir="ltr">
          <span className="block truncate">RPZ · {done[key("sync")] ?? `${c.domain} CNAME .`}</span>
          <span className="block opacity-75">zone rpz.saqr-intel.ae</span>
        </p>
      )}

      <button
        type="button"
        disabled={busy !== null}
        onClick={() => run("warn", async () => (await broadcastWarning(warningFor(c))).warning.id)}
        className="flex w-full items-center justify-between gap-3 press rounded-2xl bg-gold-500 px-4 py-3 text-start text-sm font-bold text-navy-950 transition hover:brightness-105 disabled:opacity-70"
      >
        <span className="flex items-center gap-2">
          {busy === "warn" ? <Loader2 className="size-4 animate-spin" /> : <Megaphone className="size-4" />}
          {L("broadcast")}
        </span>
        {done[key("warn")] && (
          <span className="inline-flex -rotate-3 items-center gap-1 rounded-md border-2 border-navy-950 px-2 py-1 text-[11px] leading-none font-extrabold uppercase tracking-[0.1em]">
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
        className="flex w-full items-center gap-2 press rounded-2xl border border-line bg-canvas px-4 py-3 text-start text-sm font-bold text-ink transition hover:bg-muted disabled:opacity-70"
      >
        {busy === "dossier" ? <Loader2 className="size-4 animate-spin" /> : <FileText className="size-4" />}
        {L("dossier")}
      </button>

      {err && <p className="rounded-xl border border-scam/40 bg-scam/10 px-3 py-2 text-xs text-ink">{err}</p>}

      <DossierModal dossier={dossier} onClose={() => setDossier(null)} />
    </div>
  );
}

function DossierModal({ dossier, onClose }: { dossier: TakedownDossier | null; onClose: () => void }) {
  const { lang } = useLang();
  const L = (k: keyof typeof P) => P[k][lang];
  const d = dossier;
  const st = d ? STATUS_LABEL[d.status] : null;

  return (
    <Modal open={Boolean(d)} onClose={onClose} title={L("dossierTitle")} wide>
      {d && (
        <div className="space-y-4">
          <div className="print-area space-y-4 rounded-2xl bg-surface">
            <div className="flex items-start justify-between gap-4 border-b-4 border-navy-900 pb-3 dark:border-white/70">
              <div>
                <p className="text-xs font-bold uppercase tracking-widest text-ink-soft">{d.issuing_unit}</p>
                <p className="text-xs font-bold text-ink-soft" dir="rtl">{d.issuing_unit_ar}</p>
                <h3 className="mt-1 text-xl font-extrabold text-ink">Takedown Dossier · ملف طلب الإزالة</h3>
              </div>
              <div className="text-end">
                <p className="text-[11px] font-semibold uppercase text-ink-soft">{L("amanRef")}</p>
                <p className="font-mono text-base font-extrabold text-ink" dir="ltr">{d.aman_ref_id}</p>
              </div>
            </div>
            <Rows
              rows={[
                [L("targetDomain"), d.defanged_domain],
                [L("impersonated"), d.impersonated_entity],
                [L("riskScore"), `${d.risk_score} / 100`],
                [L("registrarAbuse"), d.all_abuse_contacts.join(", ") || d.registrar_abuse_email],
                [L("citizenReports"), d.citizen_reports_count],
                [L("channels"), d.channels.join(", ")],
                [L("campaignStatus"), st ? st[lang] : d.status],
                [L("generatedAt"), d.generated_at],
              ]}
            />
            {d.evidence ? (
              <EvidenceView ev={d.evidence} lang={lang} L={L} />
            ) : (
              <>
                <Rows
                  rows={[
                    [L("ipAddresses"), d.all_ip_addresses.join(", ") || d.ip_address],
                    [L("asn"), d.asn],
                    [L("registrar"), d.registrar],
                    [L("sslAge"), d.ssl_age],
                  ]}
                />
                <div>
                  <p className="mb-1.5 text-xs font-bold uppercase tracking-wider text-ink-soft">{L("redFlags")}</p>
                  <ReasonList flags={d.red_flags} lang={lang} L={L} />
                </div>
              </>
            )}
            <div>
              <p className="mb-1.5 text-xs font-bold uppercase tracking-wider text-ink-soft">{L("requestedActions")}</p>
              <ol className="list-decimal space-y-1 ps-5 text-sm text-ink" dir="ltr">
                {d.requested_actions.map((a) => (
                  <li key={a}>{a}</li>
                ))}
              </ol>
            </div>
          </div>
          <DossierActions data={d} L={L} dossierId={d.evidence?.dossier_id} fileName={`${d.aman_ref_id}-takedown-dossier.json`} />
        </div>
      )}
    </Modal>
  );
}
