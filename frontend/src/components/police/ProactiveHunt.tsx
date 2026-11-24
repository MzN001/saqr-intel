"use client";

import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, Crosshair, Loader2, Play, ShieldAlert, UserCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Modal } from "@/components/Modal";
import { useLang } from "@/lib/i18n";
import {
  P,
  getDetectionDossier,
  getHunterStatus,
  startHunterSweep,
  type DetectionDossier,
  type HunterMode,
  type ProactiveDetection,
  type SweepCycle,
} from "@/lib/police";
import { DetectionSummary, DossierActions, EvidenceView, PrintBrand, ReasonList } from "./EvidenceDossier";
import { Card, SOURCE_STYLE, fmtHours, riskTone, timeAgo, verdictLabel, type L } from "./ui";

type Sweep = { state: "idle" } | { state: "running" } | { state: "done"; cycle: SweepCycle | null } | { state: "error"; message: string };

function CitizenLine({ d, L }: { d: ProactiveDetection; L: L }) {
  if (!d.citizen_visits) {
    return (
      <span className="inline-flex items-center gap-1 text-safe-ink">
        <UserCheck className="size-3.5" /> {L("noCitizenYet")}
      </span>
    );
  }
  const blocked = d.citizen_visits_blocked ?? 0;
  return (
    <span className="inline-flex items-center gap-1 text-ink">
      <ShieldAlert className="size-3.5" /> {L("citizensMet")}: <b className="tabular-nums" dir="ltr">{d.citizen_visits}</b>
      {" — "}
      {blocked === d.citizen_visits ? L("allBlocked") : <span dir="ltr">{blocked}/{d.citizen_visits} {L("blockedOf")}</span>}
    </span>
  );
}

export function ProactiveHunt({ detections, mode, onSwept, className = "" }: {
  detections: ProactiveDetection[];
  mode: HunterMode | undefined;
  onSwept: () => void;
  className?: string;
}) {
  const { lang } = useLang();
  const L: L = (k) => P[k][lang];
  const [sweep, setSweep] = useState<Sweep>({ state: "idle" });
  const [open, setOpen] = useState<ProactiveDetection | null>(null);
  const [dossier, setDossier] = useState<DetectionDossier | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const runSweep = async () => {
    setSweep({ state: "running" });
    try {
      const r = await startHunterSweep();
      if (r.cycle) {
        setSweep({ state: "done", cycle: r.cycle });
        onSwept();
        return;
      }
      // The cycle runs in the background: follow it until the hunter is idle again (max ~5 min).
      for (let i = 0; i < 150 && alive.current; i++) {
        await new Promise((res) => window.setTimeout(res, 2000));
        const st = await getHunterStatus();
        if (!st.cycle_running) {
          if (alive.current) setSweep({ state: "done", cycle: st.last_cycle });
          onSwept();
          return;
        }
      }
      if (alive.current) setSweep({ state: "idle" });
    } catch (e) {
      if (alive.current) setSweep({ state: "error", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const openDossier = async (d: ProactiveDetection) => {
    setOpen(d);
    setDossier(null);
    setLoadErr(null);
    try {
      const res = await getDetectionDossier(d.id);
      setDossier(res);
    } catch (e) {
      setLoadErr(e instanceof Error ? e.message : String(e));
    }
  };

  const off = mode === "off";
  const modeBadge =
    mode === "simulated" ? (
      <span className="chip-tag">{L("simulated")}</span>
    ) : mode === "live" ? (
      <span className="chip chip-suspicious uppercase tracking-widest"><span className="size-1.5 rounded-full bg-suspicious" aria-hidden />{L("liveHunt")}</span>
    ) : null;

  return (
    <Card
      className={className}
      title={L("hunt")}
      icon={<Crosshair className="size-4" />}
      right={
        <span className="flex items-center gap-2">
          {modeBadge}
          <button type="button" disabled={off || sweep.state === "running"} onClick={() => void runSweep()}
            className="btn-brand">
            {sweep.state === "running" ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
            {sweep.state === "running" ? L("sweeping") : L("runSweep")}
          </button>
        </span>
      }
    >
      <p className="mb-2 text-xs text-ink-soft">{off ? L("hunterOff") : L("huntHint")}</p>
      {mode === "simulated" && <p className="mb-2 rounded-xl bg-suspicious-soft px-3 py-1.5 text-xs text-suspicious-ink">{L("simulatedHint")}</p>}
      {sweep.state === "done" && (
        <p className="mb-2 flex flex-wrap items-center gap-x-2 rounded-xl bg-safe-soft px-3 py-1.5 text-xs text-safe-ink" role="status">
          <CheckCircle2 className="size-3.5" /> {L("sweepDone")}
          {sweep.cycle && !sweep.cycle.skipped && (
            <span dir="ltr" className="tabular-nums">
              · {sweep.cycle.leads ?? 0} {L("sweepLeads")} · {sweep.cycle.scanned ?? 0} {L("sweepScanned")} · {sweep.cycle.confirmed ?? 0} {L("sweepConfirmed")}
            </span>
          )}
        </p>
      )}
      {sweep.state === "error" && (
        <p className="mb-2 rounded-xl bg-scam-soft px-3 py-1.5 text-xs text-scam-ink" role="alert">
          {L("failed")}: {sweep.message}
        </p>
      )}

      <ul className="max-h-[360px] space-y-2 overflow-y-auto pe-1">
        {detections.length === 0 && <li className="p-4 text-sm text-ink-soft">{off ? L("hunterOff") : L("noDetections")}</li>}
        <AnimatePresence initial={false}>
          {detections.map((d) => {
            const src = SOURCE_STYLE[d.source];
            return (
              <motion.li key={d.id} layout initial={{ opacity: 0, y: -14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                transition={{ type: "spring", stiffness: 380, damping: 32 }}>
                <button type="button" onClick={() => void openDossier(d)}
                  className="w-full rounded-xl border-t border-line p-3 text-start transition hover:bg-muted">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-extrabold uppercase tracking-wide ring-1 ${src?.tone ?? "bg-muted text-ink ring-line"}`}>
                      {src ? L(src.key) : d.source}
                    </span>
                    {d.simulated && <span className="chip-tag">{L("simulated")}</span>}
                    <span className="min-w-0 flex-1 truncate font-mono text-sm font-bold text-ink" dir="ltr">{d.defanged_domain}</span>
                    <span className={`rounded-full px-2 py-0.5 text-xs font-bold tabular-nums ${riskTone(d.score)}`} dir="ltr">{d.score}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-ink-soft">
                    <span className="font-semibold text-ink-soft">{d.entity ?? "—"}</span>
                    <span>·</span>
                    <span>{d.status === "confirmed" ? L("statusConfirmed") : verdictLabel(d.verdict, L)}</span>
                    {d.domain_age_hours !== null && (
                      <>
                        <span>·</span>
                        <span>{L("domainAge")}: <span dir="ltr">{fmtHours(d.domain_age_hours, L)}</span></span>
                      </>
                    )}
                    <span>·</span>
                    <span>{L("detected")} {timeAgo(d.first_seen, lang)}</span>
                  </div>
                  <div className="mt-1 text-[11px]">
                    <CitizenLine d={d} L={L} />
                  </div>
                </button>
              </motion.li>
            );
          })}
        </AnimatePresence>
      </ul>

      <Modal open={open !== null} onClose={() => setOpen(null)} title={`${L("openDossier")} · ${open?.defanged_domain ?? ""}`} wide>
        {!dossier && !loadErr && (
          <p className="flex items-center gap-2 text-sm text-ink-soft"><Loader2 className="size-4 animate-spin" /> {L("loadingDossier")}</p>
        )}
        {loadErr && <p className="rounded-xl bg-scam-soft px-3 py-2 text-sm text-scam-ink" role="alert">{L("failed")}: {loadErr}</p>}
        {dossier && (
          <div className="space-y-4">
            <div className="print-area space-y-4 rounded-2xl bg-surface">
              <PrintBrand L={L} />
              {dossier.evidence ? (
                <EvidenceView ev={dossier.evidence} lang={lang} L={L} />
              ) : (
                <>
                  <DetectionSummary det={dossier.detection} L={L} />
                  <p className="border-t border-line pt-2 text-sm text-ink-soft">
                    {dossier.detection.simulated ? L("noEvidenceSim") : L("noEvidenceLead")}
                  </p>
                </>
              )}
              {dossier.triage_reasons.length > 0 && (
                <section>
                  <h4 className="label-caps mb-1.5">{L("triageReasons")}</h4>
                  <ReasonList flags={dossier.triage_reasons} lang={lang} L={L} />
                </section>
              )}
            </div>
            <DossierActions data={dossier} L={L} dossierId={dossier.evidence?.dossier_id}
              fileName={`${dossier.evidence?.case_reference ?? `HUNT-${dossier.detection.detection_id}`}-evidence.json`} />
          </div>
        )}
      </Modal>
    </Card>
  );
}
