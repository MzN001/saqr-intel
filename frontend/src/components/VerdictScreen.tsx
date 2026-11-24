"use client";

import { AnimatePresence, animate, motion, useMotionValue, useTransform } from "framer-motion";
import {
  ArrowLeft,
  BadgeCheck,
  Bot,
  BrainCircuit,
  CircleCheck,
  Clock,
  CreditCard,
  Download,
  ExternalLink,
  EyeOff,
  FileText,
  Fingerprint,
  Flag,
  Info,
  KeyRound,
  Languages,
  Link2Off,
  Lock,
  Mail,
  Megaphone,
  Network,
  Paperclip,
  PhoneCall,
  RefreshCw,
  ScanEye,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  ThumbsDown,
  ThumbsUp,
  TriangleAlert,
  UserRound,
  X,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import {
  ApiError,
  emailModelDownloadUrl,
  FALSE_ALARM_NOTE_MAX,
  getCampaigns,
  labelEmail,
  reportFalseAlarm,
  type CampaignMatch,
  type CampaignReference,
  type EmailAttachment,
  type EmailDetails,
  type EmailLabel,
  type EmailLink,
  type InterceptionChannel,
  type RedFlag,
  type ScanVerdict,
  type UnicodeFinding,
  type UserModelInfo,
} from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import { CHANNEL_DICT_KEY as CHANNEL_KEY, defang, warningFromVerdict } from "@/lib/share";
import { XAlertPrompt } from "./XAlertComposer";

export type ScanState =
  | { status: "idle" }
  | { status: "scanning"; target: string; interception: InterceptionChannel; kind?: ScanVerdict["kind"] }
  | { status: "done"; result: ScanVerdict }
  | { status: "error"; target: string; interception: InterceptionChannel; message: string };

const HARVEST_LABELS: Record<string, { en: string; ar: string; icon: typeof CreditCard }> = {
  OTP: { en: "OTP codes", ar: "رموز التحقق", icon: KeyRound },
  CARD_NUMBER: { en: "Card number", ar: "رقم البطاقة", icon: CreditCard },
  CVV: { en: "CVV", ar: "رمز CVV", icon: CreditCard },
  CARD_EXPIRY: { en: "Card expiry", ar: "تاريخ انتهاء البطاقة", icon: CreditCard },
  UAE_PASS: { en: "UAE PASS login", ar: "دخول UAE PASS", icon: Fingerprint },
  EMIRATES_ID: { en: "Emirates ID", ar: "الهوية الإماراتية", icon: Fingerprint },
  PASSWORD: { en: "Password", ar: "كلمة المرور", icon: KeyRound },
  ATM_PIN: { en: "ATM PIN", ar: "الرقم السري", icon: KeyRound },
  IBAN: { en: "Bank account", ar: "الحساب البنكي", icon: CreditCard },
};

const SEVERITY_STYLE: Record<RedFlag["severity"], string> = {
  critical: "bg-crimson-600 text-white",
  high: "bg-crimson-50 text-crimson-700 dark:bg-crimson-600/20 dark:text-red-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300",
  low: "bg-line text-ink-soft",
  info: "bg-line text-ink-soft",
};

const SEVERITY_LABEL: Record<RedFlag["severity"], DictKey> = {
  critical: "sevCritical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "sevInfo",
};

const VERDICT_LABEL: Record<string, DictKey> = {
  "HIGH-RISK SCAM": "verdictHighRisk",
  SUSPICIOUS: "verdictSuspicious",
  SAFE: "verdictSafe",
};

/** Look-alike findings repeat when the same text is seen twice (e.g. a link and its visible text): show each once. */
function uniqueFindings(findings: UnicodeFinding[]): UnicodeFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.where}\u0000${f.kind}\u0000${f.sample_escaped}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const SCAN_STEPS: DictKey[] = ["stepIntercept", "stepRegistry", "stepSandbox", "stepAi", "stepPolice"];

// ---------------------------------------------------------------- email verdict panels (kind "email")

/** Bidi controls (U+202A-202E, U+2066-2069) can make "invoice<RLO>fdp.exe" read as "invoiceexe.pdf".
 *  Show them as a visible marker instead of letting them reorder the text on screen. */
function visible(text: string | null | undefined): string {
  return (text ?? "").replace(/[\u202a-\u202e\u2066-\u2069]/g, "⟨⇄⟩");
}

const EMAIL_SCAN_STEPS: DictKey[] = ["emStepParse", "emStepAuth", "emStepUnicode", "emStepLinks", "emStepAi", "stepPolice"];

const AUTH_LABEL: Record<string, { key: DictKey; style: string }> = {
  pass: { key: "emAuthPass", style: "bg-emerald-600 text-white" },
  fail: { key: "emAuthFail", style: "bg-crimson-600 text-white" },
  softfail: { key: "emAuthSoft", style: "bg-amber-500 text-white" },
  neutral: { key: "emAuthNeutral", style: "bg-line text-ink-soft" },
  none: { key: "emAuthNone", style: "bg-line text-ink-soft" },
  temperror: { key: "emAuthError", style: "bg-line text-ink-soft" },
  permerror: { key: "emAuthError", style: "bg-amber-500 text-white" },
  not_checked: { key: "emAuthNotChecked", style: "bg-line text-ink-soft" },
};

const WHERE_LABEL: Record<string, DictKey> = {
  "from.domain": "emWhereFromDomain",
  "from.address": "emWhereFromAddress",
  reply_to: "emWhereReplyTo",
  return_path: "emWhereReturnPath",
  subject: "emWhereSubject",
  display_name: "emWhereDisplayName",
  body: "emWhereBody",
  link: "emWhereLink",
  attachment: "emWhereAttachment",
};

const KIND_LABEL: Record<string, DictKey> = {
  punycode: "emKindPunycode",
  mixed_script: "emKindMixed",
  whole_script_confusable: "emKindWhole",
  invisible: "emKindInvisible",
  bidi: "emKindBidi",
  fancy: "emKindFancy",
};

const VERDICT_CHIP: Record<string, string> = {
  "HIGH-RISK SCAM": "bg-crimson-600 text-white",
  SUSPICIOUS: "bg-amber-500 text-white",
  SAFE: "bg-emerald-600 text-white",
};

const MAX_LINKS_SHOWN = 10;

function Card({ title, icon: Icon, children, delay = 0.3 }: { title: string; icon: typeof Mail; children: ReactNode; delay?: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line"
    >
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-ink-soft/80">
        <Icon className="size-4" /> {title}
      </p>
      <div className="mt-2">{children}</div>
    </motion.div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-0.5 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-3">
      <dt className="text-xs font-semibold text-ink-soft/80 sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 text-sm text-ink">{children}</dd>
    </div>
  );
}

function SenderCard({ email }: { email: EmailDetails }) {
  const { t } = useLang();
  const from = email.from;
  const replyTo = email.replyTo && email.replyTo.address && email.replyTo.address !== from?.address ? email.replyTo : null;
  const realLetters = from && from.unicode_domain && from.unicode_domain !== from.domain ? from.unicode_domain : null;
  return (
    <Card title={t("emSender")} icon={UserRound} delay={0.3}>
      {from ? (
        <dl className="space-y-2.5">
          {from.display_name && (
            <Row label={t("emShownName")}>
              <span className="font-bold" dir="auto">
                {visible(from.display_name)}
              </span>
            </Row>
          )}
          <Row label={t("emRealAddress")}>
            <span className="flex flex-wrap items-center gap-1.5">
              <span dir="ltr" className="break-all font-mono font-bold">
                {visible(from.address) || "—"}
              </span>
              {from.is_freemail && (
                <span className="rounded-md bg-amber-100 px-1.5 py-0.5 text-[11px] font-bold uppercase text-amber-800 dark:bg-amber-500/20 dark:text-amber-300">
                  {t("emFreemail")}
                </span>
              )}
              {/* Green only when DMARC proves it: a spoofed From: noreply@tamm.abudhabi must not get a green badge. */}
              {from.is_official && email.auth?.dmarc?.result === "pass" && (
                <span className="inline-flex items-center gap-1 rounded-md bg-emerald-600 px-1.5 py-0.5 text-[11px] font-bold uppercase text-white">
                  <BadgeCheck className="size-3" /> {t("emOfficial")}
                </span>
              )}
              {from.is_official && email.auth?.dmarc?.result !== "pass" && (
                <span className="rounded-md bg-amber-100 px-1.5 py-0.5 text-[11px] font-bold uppercase text-amber-800 dark:bg-amber-500/20 dark:text-amber-300">
                  {t("emOfficialUnproven")}
                </span>
              )}
            </span>
          </Row>
          {realLetters && (
            <Row label={t("emRealLetters")}>
              <span dir="ltr" className="flex flex-wrap items-center gap-2 font-mono">
                <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{from.domain}</span>
                <span aria-hidden>=</span>
                <span className="rounded bg-crimson-50 px-1.5 py-0.5 font-bold text-crimson-700 dark:bg-crimson-600/20 dark:text-red-300">
                  {visible(realLetters)}
                </span>
              </span>
            </Row>
          )}
          {replyTo && (
            <Row label={t("emReplyTo")}>
              <span dir="ltr" className="break-all font-mono">
                {visible(replyTo.address)}
              </span>
            </Row>
          )}
          {email.subject && (
            <Row label={t("emSubject")}>
              <span dir="auto" className="break-words">
                {visible(email.subject)}
              </span>
            </Row>
          )}
        </dl>
      ) : (
        <p className="text-sm text-ink-soft">{t("emNoSender")}</p>
      )}
    </Card>
  );
}

function AuthChip({ name, result, meaning, extra }: { name: string; result: string; meaning: string; extra?: string | null }) {
  const { t } = useLang();
  const label = AUTH_LABEL[result] ?? AUTH_LABEL.not_checked;
  return (
    <li className="flex items-start gap-3 rounded-xl bg-muted p-3">
      <span dir="ltr" className="w-14 shrink-0 pt-0.5 font-mono text-xs font-extrabold text-ink">
        {name}
      </span>
      <span className="min-w-0 flex-1 text-sm leading-snug text-ink-soft">{meaning}</span>
      <span className="flex shrink-0 flex-col items-end gap-1">
        <span className={`rounded-md px-1.5 py-0.5 text-[11px] font-bold uppercase ${label.style}`}>{t(label.key)}</span>
        {extra && (
          <span dir="ltr" className="font-mono text-[11px] text-ink-soft/80">
            {extra}
          </span>
        )}
      </span>
    </li>
  );
}

function AuthCard({ email }: { email: EmailDetails }) {
  const { t } = useLang();
  const auth = email.auth;
  if (!email.hasHeaders || !auth) {
    return (
      <Card title={t("emAuthTitle")} icon={KeyRound} delay={0.45}>
        <p className="flex items-start gap-2 text-sm leading-relaxed text-ink-soft">
          <Info className="mt-0.5 size-4 shrink-0" /> {t("emNoHeaders")}
        </p>
      </Card>
    );
  }
  const dkims = auth.dkim ?? [];
  const dkim = dkims.find((d) => d.result === "pass" && d.aligned) ?? dkims.find((d) => d.result === "pass") ?? dkims[0];
  const dmarcPass = auth.dmarc?.result === "pass";
  return (
    <Card title={t("emAuthTitle")} icon={KeyRound} delay={0.45}>
      <ul className="space-y-2">
        <AuthChip name="SPF" result={auth.spf?.result ?? "not_checked"} meaning={t("emSpfMeaning")} extra={auth.spf?.domain || null} />
        <AuthChip name="DKIM" result={dkim?.result ?? "none"} meaning={t("emDkimMeaning")} extra={dkim?.domain || null} />
        <AuthChip
          name="DMARC"
          result={auth.dmarc?.result ?? "not_checked"}
          meaning={t("emDmarcMeaning")}
          extra={auth.dmarc?.policy ? `p=${auth.dmarc.policy}` : null}
        />
      </ul>
      {dmarcPass && email.from?.is_freemail && (
        <p className="mt-2 flex items-start gap-2 text-xs leading-relaxed text-amber-800 dark:text-amber-300">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" /> {t("emPassFreemail")}
        </p>
      )}
    </Card>
  );
}

function UnicodeCard({ findings }: { findings: UnicodeFinding[] }) {
  const { t } = useLang();
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4 }}
      className="rounded-2xl border border-crimson-600/20 bg-crimson-50 p-4 dark:border-crimson-600/40 dark:bg-crimson-600/15"
    >
      <p className="flex items-center gap-2 text-sm font-bold text-crimson-700 dark:text-red-300">
        <ScanEye className="size-4" /> {t("emUnicodeTitle")}
      </p>
      <p className="mt-1 text-xs leading-relaxed text-crimson-700/80 dark:text-red-200/80">{t("emUnicodeIntro")}</p>
      <ul className="mt-3 space-y-2">
        {uniqueFindings(findings).slice(0, 12).map((f, i) => (
          <li key={`${f.where}-${i}`} className="rounded-xl bg-white p-3 ring-1 ring-crimson-600/15 dark:bg-black/30 dark:ring-crimson-600/40">
            <p className="flex flex-wrap items-center gap-1.5 text-[11px] font-bold uppercase text-ink-soft">
              <span>{WHERE_LABEL[f.where] ? t(WHERE_LABEL[f.where]) : f.where}</span>
              <span aria-hidden>·</span>
              <span className="text-crimson-700 dark:text-red-300">{KIND_LABEL[f.kind] ? t(KIND_LABEL[f.kind]) : f.kind}</span>
            </p>
            <p dir="ltr" className="mt-1 break-all font-mono text-sm font-bold text-ink">
              {f.sample_escaped}
            </p>
            {f.skeleton && f.skeleton !== f.sample_escaped && (
              <p className="mt-1 text-xs text-ink-soft">
                {t("emImitates")}:{" "}
                <span dir="ltr" className="font-mono font-bold text-ink">
                  {f.skeleton}
                </span>
              </p>
            )}
          </li>
        ))}
      </ul>
    </motion.div>
  );
}

/** No link here is ever clickable: the citizen sees where it would go, defanged, and its scan verdict. */
function LinksCard({ links }: { links: EmailLink[] }) {
  const { t } = useLang();
  const shown = [...links]
    .sort((a, b) => Number(b.text_mismatch) - Number(a.text_mismatch) || (b.risk_score ?? -1) - (a.risk_score ?? -1))
    .slice(0, MAX_LINKS_SHOWN);
  return (
    <Card title={t("emLinksTitle")} icon={Link2Off} delay={0.5}>
      <ul className="space-y-2">
        {shown.map((l, i) => (
          <li key={`${l.url}-${i}`} className="rounded-xl bg-muted p-3">
            <div className="flex items-start justify-between gap-2">
              <dl className="min-w-0 space-y-1 text-xs">
                {l.display_text && (
                  <div className="flex gap-1.5">
                    <dt className="shrink-0 font-semibold text-ink-soft/80">{t("emLinkShows")}:</dt>
                    <dd dir="auto" className="min-w-0 truncate text-ink">
                      {visible(l.display_text)}
                    </dd>
                  </div>
                )}
                <div className="flex gap-1.5">
                  <dt className="shrink-0 font-semibold text-ink-soft/80">{t("emLinkOpens")}:</dt>
                  <dd dir="ltr" className="min-w-0 truncate font-mono font-bold text-ink">
                    {l.domain ? defang(l.domain) : defang(l.url)}
                  </dd>
                </div>
              </dl>
              <span
                className={`shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-bold uppercase ${
                  l.verdict ? VERDICT_CHIP[l.verdict] ?? "bg-line text-ink-soft" : "bg-line text-ink-soft"
                }`}
              >
                {l.verdict
                  ? `${VERDICT_LABEL[l.verdict] ? t(VERDICT_LABEL[l.verdict]) : l.verdict}${l.risk_score !== null ? ` · ${l.risk_score}` : ""}`
                  : t("emLinkNotScanned")}
              </span>
            </div>
            {(l.text_mismatch || l.unwrapped_from) && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {l.text_mismatch && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-crimson-50 px-2 py-0.5 text-[11px] font-semibold text-crimson-700 ring-1 ring-crimson-600/20 dark:bg-crimson-600/20 dark:text-red-300">
                    <TriangleAlert className="size-3" /> {t("emLinkMismatch")}
                  </span>
                )}
                {l.unwrapped_from && (
                  <span className="inline-flex items-center gap-1 rounded-full bg-surface px-2 py-0.5 text-[11px] font-semibold text-ink-soft ring-1 ring-line">
                    <EyeOff className="size-3" /> {t("emLinkUnwrapped")}
                  </span>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-2 flex items-center gap-1.5 text-xs text-ink-soft/80">
        <ShieldCheck className="size-3.5 shrink-0" /> {t("emLinksDisabled")}
        {links.length > MAX_LINKS_SHOWN && (
          <span>
            {" "}
            · +{links.length - MAX_LINKS_SHOWN} {t("emLinksMore")}
          </span>
        )}
      </p>
    </Card>
  );
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function AttachmentsCard({ attachments }: { attachments: EmailAttachment[] }) {
  const { t } = useLang();
  return (
    <Card title={t("emAttachTitle")} icon={Paperclip} delay={0.55}>
      <ul className="space-y-2">
        {attachments.slice(0, 20).map((a, i) => (
          <li
            key={`${a.name}-${i}`}
            className={`flex items-start gap-3 rounded-xl p-3 ${a.risky ? "bg-crimson-50 ring-1 ring-crimson-600/20 dark:bg-crimson-600/15 dark:ring-crimson-600/40" : "bg-muted"}`}
          >
            <FileText className={`mt-0.5 size-4 shrink-0 ${a.risky ? "text-crimson-600" : "text-ink-soft"}`} />
            <div className="min-w-0 flex-1">
              <p dir="ltr" className="truncate text-start font-mono text-sm font-bold text-ink">
                {visible(a.name) || "—"}
              </p>
              {a.risky && (
                <p className="mt-0.5 text-xs font-semibold text-crimson-700 dark:text-red-300">
                  {t("emAttachRisky")}
                  {a.reason ? ` · ${a.reason}` : ""}
                </p>
              )}
            </div>
            <span className="shrink-0 text-xs text-ink-soft">{formatBytes(a.size)}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function safeHttps(url: string): string | null {
  try {
    const u = new URL(url);
    return u.protocol === "https:" ? u.toString() : null;
  } catch {
    return null;
  }
}

function CampaignCard({ campaigns }: { campaigns: CampaignMatch[] }) {
  const { t, lang } = useLang();
  const [refs, setRefs] = useState<Record<string, CampaignReference[]>>({});

  // The match in the verdict has no source links: look them up in the public scam-wave feed.
  useEffect(() => {
    let alive = true;
    getCampaigns()
      .then((feed) => {
        if (!alive) return;
        const map: Record<string, CampaignReference[]> = {};
        for (const c of feed.campaigns ?? []) map[c.id] = c.references ?? [];
        setRefs(map);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.35 }}
      className="rounded-2xl bg-navy-900 p-4 text-white dark:bg-navy-800 dark:ring-1 dark:ring-white/10"
    >
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-white/60">
        <Megaphone className="size-4" /> {t("emCampaignTitle")}
      </p>
      <ul className="mt-2 space-y-3">
        {campaigns.map((c) => {
          const sources = (refs[c.id] ?? []).map((r) => ({ ...r, href: safeHttps(r.url) })).filter((r) => r.href);
          return (
            <li key={c.id}>
              <p className="text-lg font-bold leading-snug text-gold-500">{lang === "ar" ? c.title_ar || c.title_en : c.title_en}</p>
              <p className="mt-0.5 text-xs font-semibold text-white/70">{t(c.match === "ioc" ? "emCampaignIoc" : "emCampaignLure")}</p>
              {c.matched.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {c.matched.slice(0, 8).map((m) => (
                    <span key={m} dir="auto" className="rounded-full bg-white/10 px-2.5 py-0.5 text-xs ring-1 ring-white/15">
                      {c.match === "ioc" ? defang(m) : m}
                    </span>
                  ))}
                </div>
              )}
              {sources.length > 0 && (
                <div className="mt-2 text-xs">
                  <span className="font-semibold text-white/60">{t("emCampaignSources")}: </span>
                  {sources.slice(0, 4).map((r, i) => (
                    <span key={`${r.href}-${i}`}>
                      {i > 0 && " · "}
                      <a href={r.href ?? undefined} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 underline underline-offset-2 hover:text-gold-500">
                        {r.title || r.source_id} <ExternalLink className="size-3" />
                      </a>
                    </span>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </motion.div>
  );
}

function PersonalModelCard({ scanId, model }: { scanId: string; model: UserModelInfo | null }) {
  const { t } = useLang();
  const [labels, setLabels] = useState(model?.labels ?? 0);
  const [state, setState] = useState<"idle" | "saving" | "saved" | "failed">("idle");
  const [chosen, setChosen] = useState<EmailLabel | null>(null);

  const send = async (label: EmailLabel) => {
    setChosen(label);
    setState("saving");
    try {
      const r = await labelEmail(scanId, label);
      const n = typeof r?.labels === "number" ? r.labels : typeof r?.user_model?.labels === "number" ? r.user_model.labels : labels + 1;
      setLabels(n);
      setState("saved");
    } catch {
      setState("failed");
    }
  };

  const line =
    model?.available && model.p_scam !== null
      ? t("emModelScore").replace("{p}", String(Math.round(model.p_scam * 100))).replace("{n}", String(labels))
      : t("emModelLearning").replace("{n}", String(labels));

  return (
    <Card title={t("emModelTitle")} icon={BrainCircuit} delay={0.6}>
      <p className="text-sm font-semibold text-ink">{line}</p>
      <p className="mt-1 text-xs leading-relaxed text-ink-soft">{t("emModelAsk")}</p>
      <div className="mt-3 grid grid-cols-2 gap-2">
        {(
          [
            ["scam", "emLabelScam", ThumbsDown, "bg-crimson-600 text-white ring-crimson-600"],
            ["ham", "emLabelHam", ThumbsUp, "bg-emerald-600 text-white ring-emerald-600"],
          ] as const
        ).map(([label, key, Icon, activeStyle]) => (
          <button
            key={label}
            type="button"
            disabled={state === "saving"}
            onClick={() => void send(label)}
            aria-pressed={chosen === label && state === "saved"}
            className={`inline-flex items-center justify-center gap-2 rounded-2xl px-3 py-2.5 text-sm font-bold ring-1 transition disabled:opacity-60 ${
              chosen === label && state === "saved" ? activeStyle : "bg-muted text-ink ring-line hover:bg-line"
            }`}
          >
            <Icon className="size-4" /> {t(key)}
          </button>
        ))}
      </div>
      <div aria-live="polite">
        {state === "saved" && (
          <p className="mt-2 flex items-center gap-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
            <CircleCheck className="size-3.5" /> {t("emLabelSaved")}
          </p>
        )}
        {state === "failed" && (
          <p className="mt-2 flex items-center gap-1.5 text-xs font-semibold text-amber-800 dark:text-amber-300">
            <TriangleAlert className="size-3.5" /> {t("emLabelFailed")}
          </p>
        )}
      </div>
      <a
        href={emailModelDownloadUrl()}
        download="saqr-my-model.json"
        className="mt-3 inline-flex items-center gap-1.5 text-xs font-bold text-ink underline underline-offset-2 hover:text-emerald-700 dark:hover:text-emerald-400"
      >
        <Download className="size-3.5" /> {t("emModelDownload")}
      </a>
    </Card>
  );
}

function LlmNote({ email }: { email: EmailDetails }) {
  const { t } = useLang();
  if (email.userLlmError) {
    return (
      <p className="flex items-start gap-2 rounded-2xl bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-500/30 dark:bg-amber-500/15 dark:text-amber-200">
        <Bot className="mt-0.5 size-4 shrink-0" />
        <span>
          {t("llmFailed")} <span className="text-xs opacity-80">({email.userLlmError})</span>
        </span>
      </p>
    );
  }
  if (!email.userLlmHost) return null;
  return (
    <p className="flex items-center gap-2 rounded-2xl bg-surface p-3 text-sm text-ink-soft ring-1 ring-line">
      <Bot className="size-4 shrink-0" /> {t("llmUsed")}{" "}
      <span dir="ltr" className="font-mono text-xs">
        ({email.userLlmHost})
      </span>
    </p>
  );
}

function AiNotes({ notes }: { notes: string[] }) {
  const { t } = useLang();
  return (
    <Card title={t("emAiNotes")} icon={Sparkles} delay={0.5}>
      <ul className="space-y-1.5">
        {notes.slice(0, 6).map((n, i) => (
          <li key={i} className="flex gap-2 text-sm text-ink" dir="auto">
            <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-crimson-600" />
            <span>{n}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function stripBullets(text: string): string {
  return text
    .split(/\n\s*\n/)
    .filter((p) => !/^\s*(red flags|علامات الخطر)\s*:/i.test(p) && !/^\s*•/.test(p))
    .join("\n\n")
    .trim();
}

function RiskGauge({ score, tone }: { score: number; tone: "danger" | "warn" | "safe" }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const value = useMotionValue(0);
  const offset = useTransform(value, (v) => circumference - (v / 100) * circumference);
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    const controls = animate(value, score, { duration: 1.4, ease: [0.16, 1, 0.3, 1] });
    const unsub = value.on("change", (v) => setDisplay(Math.round(v)));
    return () => {
      controls.stop();
      unsub();
    };
  }, [score, value]);

  const glow = tone === "danger" ? "rgba(255,180,190,0.9)" : tone === "warn" ? "rgba(255,230,160,0.9)" : "rgba(170,255,215,0.9)";
  return (
    <div className="relative grid size-36 shrink-0 place-items-center">
      <svg viewBox="0 0 128 128" className="absolute inset-0 -rotate-90">
        <circle cx="64" cy="64" r={radius} fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="10" />
        <motion.circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke="#ffffff"
          strokeWidth="10"
          style={{ strokeDashoffset: offset, filter: `drop-shadow(0 0 6px ${glow})` }}
          strokeLinecap="round"
          strokeDasharray={circumference}
        />
      </svg>
      <div className="text-center">
        <div className="text-4xl font-extrabold tabular-nums text-white">{display}</div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-white/70">/ 100</div>
      </div>
    </div>
  );
}

function ScanningView({ target, interception, kind }: { target: string; interception: InterceptionChannel; kind?: ScanVerdict["kind"] }) {
  const { t } = useLang();
  const [step, setStep] = useState(0);
  const isEmail = kind === "email";
  const steps = isEmail ? EMAIL_SCAN_STEPS : SCAN_STEPS;
  useEffect(() => {
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, steps.length - 1)), isEmail ? 520 : 650);
    return () => window.clearInterval(id);
  }, [steps.length, isEmail]);

  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-navy-900 px-6 py-16 text-white">
      <div className="relative grid size-56 place-items-center overflow-hidden rounded-full">
        {[0, 1, 2].map((i) => (
          <span key={i} className="absolute inset-0 rounded-full border border-emerald-400/30" style={{ transform: `scale(${0.45 + i * 0.27})` }} />
        ))}
        <span className="absolute inset-0 animate-sweep rounded-full bg-[conic-gradient(from_0deg,rgba(16,185,129,0.55),transparent_28%)]" />
        <span className="absolute size-20 animate-ping-slow rounded-full bg-emerald-400/30" />
        <div className="relative grid size-20 place-items-center rounded-2xl bg-white/10 ring-1 ring-white/20 backdrop-blur">
          {isEmail ? <Mail className="size-10 text-emerald-300" /> : <ShieldCheck className="size-10 text-emerald-300" />}
        </div>
      </div>
      <p className="mt-6 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-emerald-300">
        {t(CHANNEL_KEY[interception])}
      </p>
      <h2 className="shimmer-text mt-3 text-center text-2xl font-bold">{t(isEmail ? "emScanningTitle" : "scanningTitle")}</h2>
      <p className="mt-2 max-w-xs truncate text-center font-mono text-sm text-white/60" dir="ltr">
        {visible(target)}
      </p>
      <ul className="mt-8 w-full max-w-sm space-y-2.5">
        {steps.map((key, i) => (
          <motion.li
            key={key}
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: i <= step ? 1 : 0.35, x: 0 }}
            transition={{ delay: i * 0.08 }}
            className="flex items-center gap-3 text-sm"
          >
            {i < step ? (
              <CircleCheck className="size-5 text-emerald-400" />
            ) : i === step ? (
              <RefreshCw className="size-5 animate-spin text-emerald-300" />
            ) : (
              <span className="size-5 rounded-full border border-white/30" />
            )}
            <span>{t(key)}</span>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}

type ReportState = "closed" | "open" | "sending" | "sent" | "already" | "error";

/** One-line privacy note, plus (for warnings only) a quiet "Report a false alarm" control. */
function PrivacyAndFeedback({ scanId, canReport }: { scanId: string; canReport: boolean }) {
  const { t } = useLang();
  const [state, setState] = useState<ReportState>("closed");
  const [note, setNote] = useState("");
  const [error, setError] = useState<DictKey>("faFailed");
  const showReport = canReport && Boolean(scanId);

  const send = async () => {
    setState("sending");
    try {
      const r = await reportFalseAlarm(scanId, note);
      setState(r.deduplicated ? "already" : "sent");
    } catch (e) {
      const status = e instanceof ApiError ? e.status : 0;
      setError(status === 429 ? "faRateLimited" : status === 404 ? "faNotFound" : "faFailed");
      setState("error");
    }
  };

  return (
    <section className="space-y-3 border-t border-line pt-4">
      <p className="flex items-start gap-2 text-xs leading-relaxed text-ink-soft">
        <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden /> {t("privacyLine")}
      </p>
      {showReport && (
        <div aria-live="polite">
          {state === "closed" && (
            <button
              type="button"
              onClick={() => setState("open")}
              className="inline-flex items-center gap-1.5 rounded-xl px-2 py-1.5 text-xs font-semibold text-ink-soft underline-offset-2 hover:bg-muted hover:text-ink hover:underline"
            >
              <Flag className="size-3.5" aria-hidden /> {t("faReport")}
            </button>
          )}
          {(state === "open" || state === "sending" || state === "error") && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void send();
              }}
              className="space-y-2"
            >
              <label htmlFor={`fa-note-${scanId}`} className="block text-xs font-semibold text-ink">
                {t("faNoteLabel")}
              </label>
              <textarea
                id={`fa-note-${scanId}`}
                value={note}
                onChange={(e) => setNote(e.target.value.slice(0, FALSE_ALARM_NOTE_MAX))}
                maxLength={FALSE_ALARM_NOTE_MAX}
                rows={2}
                dir="auto"
                placeholder={t("faNotePlaceholder")}
                className="w-full resize-none rounded-xl bg-surface px-[13px] py-[9px] text-sm text-ink outline-hidden ring-1 ring-line transition-shadow placeholder:text-ink-soft/70 focus:ring-2 focus:ring-emerald-600"
              />
              <p className="flex justify-between gap-3 text-[11px] text-ink-soft">
                <span>{t("faSentWhat")}</span>
                <span className="shrink-0 tabular-nums" dir="ltr">
                  {note.length}/{FALSE_ALARM_NOTE_MAX}
                </span>
              </p>
              {state === "error" && (
                <p className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                  <TriangleAlert className="size-3.5 shrink-0" aria-hidden /> {t(error)}
                </p>
              )}
              <div className="flex flex-wrap gap-2">
                <button
                  type="submit"
                  disabled={state === "sending"}
                  className="rounded-xl border border-line px-3 py-2 text-xs font-bold text-ink hover:bg-muted disabled:opacity-60"
                >
                  {t(state === "sending" ? "faSending" : "faSend")}
                </button>
                <button
                  type="button"
                  onClick={() => setState("closed")}
                  className="rounded-xl px-3 py-2 text-xs font-semibold text-ink-soft hover:text-ink"
                >
                  {t("faCancel")}
                </button>
              </div>
            </form>
          )}
          {(state === "sent" || state === "already") && (
            <p className="flex items-center gap-1.5 text-xs font-semibold text-ink">
              <CircleCheck className="size-3.5 shrink-0" aria-hidden /> {t(state === "sent" ? "faThanks" : "faAlready")}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function ResultView({ result, onClose }: { result: ScanVerdict; onClose: () => void }) {
  const { t, lang } = useLang();
  const [showOther, setShowOther] = useState(false);
  const tone = result.verdict === "HIGH-RISK SCAM" ? "danger" : result.verdict === "SUSPICIOUS" ? "warn" : "safe";
  const header =
    tone === "danger"
      ? "from-crimson-700 via-crimson-600 to-[#7a0a1c]"
      : tone === "warn"
        ? "from-amber-600 via-amber-500 to-amber-700"
        : "from-emerald-700 via-emerald-600 to-emerald-800";
  const entity = (lang === "ar" ? result.entityAr : result.entityEn) ?? result.entityEn ?? t("unknownEntity");
  const primary = stripBullets(lang === "ar" ? result.explanationAr : result.explanationEn);
  const secondary = stripBullets(lang === "ar" ? result.explanationEn : result.explanationAr);
  const official = result.officialDomains[0];
  const syndicate = lang === "ar" ? result.syndicateAr ?? result.syndicateEn : result.syndicateEn;
  const email = result.kind === "email" ? result.email ?? null : null;
  const title = email
    ? t(tone === "danger" ? "emBlockedTitle" : tone === "warn" ? "emSuspiciousTitle" : "emSafeTitle")
    : t(tone === "danger" ? "blockedTitle" : tone === "warn" ? "suspiciousTitle" : "safeTitle");
  const HeaderIcon = tone === "safe" ? ShieldCheck : tone === "warn" ? TriangleAlert : ShieldAlert;

  return (
    <div className="min-h-full bg-canvas">
      <div className={`relative overflow-hidden bg-gradient-to-br ${header} px-5 pb-8 pt-5 text-white`}>
        <div className="pointer-events-none absolute -end-16 -top-16 size-56 rounded-full bg-white/10 blur-2xl" />
        <div className="relative mx-auto max-w-2xl">
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-semibold">
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">AD Police</span>
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">e&amp;</span>
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">du</span>
              <span className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">{t(CHANNEL_KEY[result.interception])}</span>
            </div>
            <button onClick={onClose} aria-label={t("close")} className="rounded-full bg-white/15 p-2 hover:bg-white/25">
              <X className="size-5" />
            </button>
          </div>

          <div className="mt-6 flex items-center gap-5">
            <RiskGauge score={result.riskScore} tone={tone} />
            <div className="min-w-0">
              <motion.div
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring", stiffness: 260, damping: 14, delay: 0.2 }}
                className="mb-2 inline-flex items-center gap-2 rounded-lg bg-white px-2.5 py-1 text-sm font-extrabold tracking-wide"
                style={{ color: tone === "danger" ? "#c8102e" : tone === "warn" ? "#b45309" : "#047857" }}
              >
                <HeaderIcon className="size-4" /> {VERDICT_LABEL[result.verdict] ? t(VERDICT_LABEL[result.verdict]) : result.verdict}
              </motion.div>
              <h2 className="text-2xl font-extrabold leading-tight sm:text-3xl">{title}</h2>
              {email ? (
                <p className="mt-1 text-sm text-white/80">{t("emCheckedBy")}</p>
              ) : (
                tone !== "safe" && <p className="mt-1 text-sm text-white/80">{t("blockedBy")}</p>
              )}
              <p className="mt-2 truncate font-mono text-xs text-white/70" dir="ltr">
                {visible(result.target)}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto -mt-4 max-w-2xl space-y-4 px-4 pb-10">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="relative overflow-hidden rounded-2xl bg-navy-900 p-4 text-white shadow-lg dark:bg-navy-800 dark:ring-1 dark:ring-white/10"
        >
          <div className="flex items-center gap-3">
            <span className="relative flex size-3">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex size-3 rounded-full bg-emerald-400" />
            </span>
            <p className="text-sm font-semibold">{t("syncedBadge")}</p>
          </div>
          <p className="mt-1 ps-6 font-mono text-xs text-white/60" dir="ltr">
            {t("caseId")} {result.scanId} · {new Date().toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE")}
          </p>
        </motion.div>

        {tone !== "safe" && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="grid gap-3 sm:grid-cols-2"
          >
            <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("impersonating")}</p>
              <p className="mt-1 text-lg font-bold text-crimson-700 dark:text-red-300">{entity}</p>
            </div>
            {official && (
              <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
                <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("officialSite")}</p>
                <p className="mt-1 flex items-center gap-2 text-lg font-bold text-emerald-700 dark:text-emerald-400" dir="ltr">
                  <ShieldCheck className="size-5" /> {official}
                </p>
              </div>
            )}
          </motion.div>
        )}

        {email && <SenderCard email={email} />}

        {result.harvested.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45 }}
            className="rounded-2xl border border-crimson-600/20 bg-crimson-50 p-4 dark:border-crimson-600/40 dark:bg-crimson-600/15"
          >
            <p className="text-sm font-bold text-crimson-700 dark:text-red-300">{t("wantsYour")}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {result.harvested
                .filter((h) => HARVEST_LABELS[h])
                .map((h) => {
                  const Icon = HARVEST_LABELS[h].icon;
                  return (
                    <span key={h} className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1 text-xs font-semibold text-crimson-700 ring-1 ring-crimson-600/20 dark:bg-black/30 dark:text-red-300 dark:ring-crimson-600/40">
                      <Icon className="size-3.5" /> {HARVEST_LABELS[h][lang]}
                    </span>
                  );
                })}
            </div>
          </motion.div>
        )}

        {primary && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line"
          >
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t(tone === "safe" ? "whySafe" : "whyDangerous")}</p>
              <button
                onClick={() => setShowOther((s) => !s)}
                className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-xs font-semibold text-ink-soft hover:bg-line"
              >
                <Languages className="size-3.5" /> {t("otherLanguage")}
              </button>
            </div>
            <p className="mt-2 whitespace-pre-line text-[15px] leading-relaxed text-ink">{primary}</p>
            <AnimatePresence>
              {showOther && secondary && (
                <motion.p
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  dir={lang === "ar" ? "ltr" : "rtl"}
                  className="mt-3 overflow-hidden whitespace-pre-line border-t border-line pt-3 text-[15px] leading-relaxed text-ink-soft"
                >
                  {secondary}
                </motion.p>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        {email && email.unicode.length > 0 && <UnicodeCard findings={email.unicode} />}
        {email && email.campaigns.length > 0 && <CampaignCard campaigns={email.campaigns} />}

        {result.redFlags.length > 0 && (
          <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("redFlags")}</p>
            <ul className="mt-2 space-y-2">
              {[...result.redFlags]
                .sort((a, b) => b.points - a.points)
                .map((f, i) => (
                  <motion.li
                    key={`${f.code}-${i}`}
                    initial={{ opacity: 0, x: lang === "ar" ? 16 : -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.55 + i * 0.07 }}
                    className="flex gap-3 rounded-xl bg-muted p-3"
                  >
                    <span className={`h-fit shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-bold uppercase ${SEVERITY_STYLE[f.severity]}`}>
                      {SEVERITY_LABEL[f.severity] ? t(SEVERITY_LABEL[f.severity]) : f.severity}
                    </span>
                    <span className="text-sm leading-snug text-ink">{lang === "ar" ? f.ar : f.en}</span>
                  </motion.li>
                ))}
            </ul>
          </div>
        )}

        {email && (
          <>
            <AuthCard email={email} />
            {email.links.length > 0 && <LinksCard links={email.links} />}
            {email.attachments.length > 0 && <AttachmentsCard attachments={email.attachments} />}
            {tone !== "safe" && email.llmRedFlags.length > 0 && <AiNotes notes={email.llmRedFlags} />}
            <LlmNote email={email} />
          </>
        )}

        {tone !== "safe" && result.riskScore >= 60 && <XAlertPrompt warning={warningFromVerdict(result)} />}

        {email && <PersonalModelCard scanId={result.scanId} model={email.userModel} />}

        {email && tone === "safe" && (
          <p className="flex items-start gap-2 rounded-2xl bg-surface p-3 text-sm text-ink-soft ring-1 ring-line">
            <Info className="mt-0.5 size-4 shrink-0" /> {t("emSafeNote")}
          </p>
        )}

        {(syndicate || result.ip || result.domainAgeHours !== null || result.cloaking) && (
          <div className="grid gap-3 sm:grid-cols-2">
            {syndicate && (
              <div className="rounded-2xl bg-navy-900 p-4 text-white sm:col-span-2 dark:bg-navy-800 dark:ring-1 dark:ring-white/10">
                <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-white/60">
                  <Network className="size-4" /> {t("syndicateLink")}
                </p>
                <p className="mt-1 text-lg font-bold text-gold-500">{syndicate}</p>
              </div>
            )}
            {result.domainAgeHours !== null && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line">
                <Clock className="size-5 text-crimson-600" />
                <div>
                  <p className="text-xs text-ink-soft/80">{t("registered")}</p>
                  <p className="font-bold">
                    {Math.round(result.domainAgeHours)} {t("hoursAgo")}
                  </p>
                </div>
              </div>
            )}
            {result.ip && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line">
                <Server className="size-5 text-ink-soft" />
                <div>
                  <p className="text-xs text-ink-soft/80">{t("hostedOn")}</p>
                  <p className="font-mono font-bold" dir="ltr">
                    {result.ip}
                  </p>
                </div>
              </div>
            )}
            {result.cloaking && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line sm:col-span-2">
                <EyeOff className="size-5 text-amber-600" />
                <p className="font-semibold">{t("cloaking")}</p>
              </div>
            )}
          </div>
        )}

        {result.screenshot && (
          <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("evidence")}</p>
            <div className="relative mt-2 overflow-hidden rounded-xl ring-1 ring-line">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`data:image/jpeg;base64,${result.screenshot}`}
                alt="Sandbox screenshot of the blocked page"
                className="max-h-80 w-full object-cover object-top opacity-90 blur-[1px] grayscale-[30%]"
              />
              <div className="absolute inset-0 grid place-items-center bg-crimson-600/10">
                <span className="rotate-[-12deg] rounded-lg border-4 border-crimson-600 bg-white/90 px-4 py-1 text-2xl font-black tracking-widest text-crimson-600">
                  BLOCKED
                </span>
              </div>
            </div>
          </div>
        )}

        <PrivacyAndFeedback key={result.scanId} scanId={result.scanId} canReport={tone !== "safe"} />

        <div className="sticky bottom-0 -mx-4 space-y-2 bg-gradient-to-t from-canvas via-canvas to-transparent px-4 pb-4 pt-6">
          <button
            onClick={onClose}
            className="flex w-full items-center justify-center gap-2 rounded-2xl bg-navy-900 py-3.5 text-base font-bold text-white shadow-lg transition hover:bg-navy-800 active:scale-[0.98] dark:bg-navy-700 dark:hover:bg-navy-800"
          >
            <ArrowLeft className="size-5 rtl:rotate-180" /> {t("backToSafety")}
          </button>
          <div className="grid grid-cols-2 gap-2">
            {tone === "safe" && email ? (
              official ? (
                <a
                  href={`https://${official}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="press col-span-2 flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 py-3 text-sm font-bold text-white"
                >
                  <ShieldCheck className="size-4" /> {t("goOfficial")}
                </a>
              ) : null
            ) : tone === "safe" ? (
              <a
                href={official ? `https://${official}` : "#"}
                target="_blank"
                rel="noopener noreferrer"
                className="press col-span-2 flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 py-3 text-sm font-bold text-white"
              >
                <ExternalLink className="size-4" /> {t("continueSite")}
              </a>
            ) : (
              <>
                {official ? (
                  <a
                    href={`https://${official}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="press flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 py-3 text-sm font-bold text-white"
                  >
                    <ShieldCheck className="size-4" /> {t("goOfficial")}
                  </a>
                ) : (
                  <span />
                )}
                <a
                  href="tel:8002626"
                  className={`flex items-center justify-center gap-2 rounded-2xl bg-surface py-3 text-sm font-bold text-ink ring-1 ring-line ${official ? "" : "col-span-2"}`}
                >
                  <PhoneCall className="size-4" /> {t("callAman")}
                </a>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ErrorView({ message, onRetry, onClose }: { message: string; onRetry: () => void; onClose: () => void }) {
  const { t } = useLang();
  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-navy-900 px-6 text-center text-white">
      <TriangleAlert className="size-14 text-amber-400" />
      <h2 className="mt-4 text-2xl font-bold">{t("scanFailed")}</h2>
      <p className="mt-2 max-w-sm text-sm text-white/70">{message}</p>
      <div className="mt-6 flex gap-3">
        <button onClick={onRetry} className="press rounded-xl bg-emerald-600 px-5 py-2.5 font-semibold">
          {t("retry")}
        </button>
        <button onClick={onClose} className="rounded-xl bg-white/10 px-5 py-2.5 font-semibold">
          {t("close")}
        </button>
      </div>
    </div>
  );
}

export function VerdictScreen({ state, onClose, onRetry }: { state: ScanState; onClose: () => void; onRetry: () => void }) {
  const open = state.status !== "idle";

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="verdict-sheet"
          role="dialog"
          aria-modal="true"
          initial={{ y: "100%" }}
          animate={{ y: 0 }}
          exit={{ y: "100%" }}
          transition={{ type: "spring", stiffness: 210, damping: 28 }}
          className="fixed inset-0 z-50 overflow-y-auto overscroll-contain bg-navy-900 no-scrollbar"
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={state.status}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="min-h-full"
            >
              {state.status === "scanning" && <ScanningView target={state.target} interception={state.interception} kind={state.kind} />}
              {state.status === "done" && <ResultView result={state.result} onClose={onClose} />}
              {state.status === "error" && <ErrorView message={state.message} onRetry={onRetry} onClose={onClose} />}
            </motion.div>
          </AnimatePresence>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
