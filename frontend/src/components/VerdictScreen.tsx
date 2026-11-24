"use client";

import { AnimatePresence, motion } from "framer-motion";
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
  MessageSquareText,
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
  type MessageDetails,
  type MessagePhone,
  type RedFlag,
  type ScanVerdict,
  type UnicodeFinding,
  type UserModelInfo,
} from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import { CHANNEL_DICT_KEY as CHANNEL_KEY, defang, warningFromVerdict } from "@/lib/share";
import { RiskMeter, TONE_CHIP, TONE_TEXT, toneOf, type Tone } from "./RiskMeter";
import { XAlertPrompt } from "./XAlertComposer";

/*
 * The full verdict report. Two uses:
 *  - `VerdictScreen`: the full-screen block page, kept for scans that start from a share, a scam-alert
 *    notification or a DNS block (the resident was about to open something).
 *  - `ResultView` (embedded): the "Full report" drawer behind the inline VerdictCard.
 * Saqr styling: white cards on the canvas, the three-zone meter, crimson only for scam, amber for
 * suspicious, emerald for safe / verified. No card sits inside another card.
 */

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

/** Severity chips: high/critical are scam evidence, medium is suspicious, low/info are neutral. */
const SEVERITY_CHIP: Record<RedFlag["severity"], string> = {
  critical: "chip chip-scam",
  high: "chip chip-scam",
  medium: "chip chip-suspicious",
  low: "chip",
  info: "chip",
};

const SEVERITY_LABEL: Record<RedFlag["severity"], DictKey> = {
  critical: "sevCritical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "sevInfo",
};

export const VERDICT_LABEL: Record<string, DictKey> = {
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
const EMAIL_SCAN_STEPS: DictKey[] = ["emStepParse", "emStepAuth", "emStepUnicode", "emStepLinks", "emStepAi", "stepPolice"];
const MESSAGE_SCAN_STEPS: DictKey[] = ["msgStepLinks", "msgStepPhones", "msgStepWording", "stepPolice"];

/** The scanning steps shown for each kind of check (also used by the inline VerdictCard). */
export function scanSteps(kind?: ScanVerdict["kind"]): DictKey[] {
  return kind === "email" ? EMAIL_SCAN_STEPS : kind === "message" ? MESSAGE_SCAN_STEPS : SCAN_STEPS;
}
export function scanTitle(kind?: ScanVerdict["kind"]): DictKey {
  return kind === "email" ? "emScanningTitle" : kind === "message" ? "msgScanningTitle" : "scanningTitle";
}

/** Bidi controls (U+202A-202E, U+2066-2069) can make "invoice<RLO>fdp.exe" read as "invoiceexe.pdf".
 *  Show them as a visible marker instead of letting them reorder the text on screen. */
export function visible(text: string | null | undefined): string {
  return (text ?? "").replace(/[‪-‮⁦-⁩]/g, "⟨⇄⟩");
}

/** A green "verified official" state is earned only by proof: an official link, an official site, or DMARC. */
export function isVerifiedOfficial(r: ScanVerdict): boolean {
  if (r.verdict !== "SAFE") return false;
  if (r.kind === "message") return Boolean(r.message?.verifiedOfficial);
  if (r.kind === "email") return Boolean(r.email?.from?.is_official && r.email.auth?.dmarc?.result === "pass");
  const host = (r.scamDomain ?? r.target ?? "").toLowerCase().replace(/^www\./, "");
  if (!host) return false;
  return r.officialDomains.some((d) => {
    const o = d.toLowerCase().replace(/^www\./, "");
    return host === o || host.endsWith(`.${o}`);
  });
}

const AUTH_LABEL: Record<string, { key: DictKey; chip: string }> = {
  pass: { key: "emAuthPass", chip: "chip chip-safe" },
  fail: { key: "emAuthFail", chip: "chip chip-scam" },
  softfail: { key: "emAuthSoft", chip: "chip chip-suspicious" },
  neutral: { key: "emAuthNeutral", chip: "chip" },
  none: { key: "emAuthNone", chip: "chip" },
  temperror: { key: "emAuthError", chip: "chip" },
  permerror: { key: "emAuthError", chip: "chip chip-suspicious" },
  not_checked: { key: "emAuthNotChecked", chip: "chip" },
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

const MAX_LINKS_SHOWN = 10;

/** One white card on the canvas, with a tracked caps title. Never nested. */
function Section({
  title,
  icon: Icon,
  children,
  delay = 0.1,
  titleClass = "",
}: {
  title: string;
  icon: typeof Mail;
  children: ReactNode;
  delay?: number;
  titleClass?: string;
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      className="card p-4 sm:p-5"
    >
      <h3 className={`label-caps flex items-center gap-2 ${titleClass}`}>
        <Icon className="size-4" aria-hidden /> {title}
      </h3>
      <div className="mt-3">{children}</div>
    </motion.section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-0.5 sm:grid-cols-[9rem_minmax(0,1fr)] sm:gap-3">
      <dt className="text-[13px] font-semibold text-ink-soft sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 text-[15px] text-ink">{children}</dd>
    </div>
  );
}

function SenderCard({ email }: { email: EmailDetails }) {
  const { t } = useLang();
  const from = email.from;
  const replyTo = email.replyTo && email.replyTo.address && email.replyTo.address !== from?.address ? email.replyTo : null;
  const realLetters = from && from.unicode_domain && from.unicode_domain !== from.domain ? from.unicode_domain : null;
  return (
    <Section title={t("emSender")} icon={UserRound}>
      {from ? (
        <dl className="space-y-2.5">
          {from.display_name && (
            <Row label={t("emShownName")}>
              <span className="font-semibold" dir="auto">
                {visible(from.display_name)}
              </span>
            </Row>
          )}
          <Row label={t("emRealAddress")}>
            <span className="flex flex-wrap items-center gap-1.5">
              <span dir="ltr" className="break-all font-mono text-[14px] font-semibold">
                {visible(from.address) || "—"}
              </span>
              {from.is_freemail && <span className="chip chip-suspicious">{t("emFreemail")}</span>}
              {/* Green only when DMARC proves it: a spoofed From: noreply@tamm.abudhabi must not get a green badge. */}
              {from.is_official && email.auth?.dmarc?.result === "pass" && (
                <span className="chip chip-safe">
                  <BadgeCheck className="size-3.5" aria-hidden /> {t("emOfficial")}
                </span>
              )}
              {from.is_official && email.auth?.dmarc?.result !== "pass" && <span className="chip chip-suspicious">{t("emOfficialUnproven")}</span>}
            </span>
          </Row>
          {realLetters && (
            <Row label={t("emRealLetters")}>
              <span dir="ltr" className="flex flex-wrap items-center gap-2 font-mono text-[14px]">
                <span className="rounded bg-muted px-1.5 py-0.5">{from.domain}</span>
                <span aria-hidden>=</span>
                <span className="rounded bg-scam-soft px-1.5 py-0.5 font-semibold text-scam-ink">{visible(realLetters)}</span>
              </span>
            </Row>
          )}
          {replyTo && (
            <Row label={t("emReplyTo")}>
              <span dir="ltr" className="break-all font-mono text-[14px]">
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
        <p className="text-[15px] text-ink-soft">{t("emNoSender")}</p>
      )}
    </Section>
  );
}

function AuthChip({ name, result, meaning, extra }: { name: string; result: string; meaning: string; extra?: string | null }) {
  const { t } = useLang();
  const label = AUTH_LABEL[result] ?? AUTH_LABEL.not_checked;
  return (
    <li className="flex items-start gap-3 py-3">
      <span dir="ltr" className="w-14 shrink-0 pt-0.5 font-mono text-[13px] font-bold text-ink">
        {name}
      </span>
      <span className="min-w-0 flex-1 text-[14px] leading-snug text-ink-soft">{meaning}</span>
      <span className="flex shrink-0 flex-col items-end gap-1">
        <span className={label.chip}>{t(label.key)}</span>
        {extra && (
          <span dir="ltr" className="font-mono text-[11px] text-ink-soft">
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
      <Section title={t("emAuthTitle")} icon={KeyRound}>
        <p className="flex items-start gap-2 text-[14px] leading-relaxed text-ink-soft">
          <Info className="mt-0.5 size-4 shrink-0" aria-hidden /> {t("emNoHeaders")}
        </p>
      </Section>
    );
  }
  const dkims = auth.dkim ?? [];
  const dkim = dkims.find((d) => d.result === "pass" && d.aligned) ?? dkims.find((d) => d.result === "pass") ?? dkims[0];
  const dmarcPass = auth.dmarc?.result === "pass";
  return (
    <Section title={t("emAuthTitle")} icon={KeyRound}>
      <ul className="-my-3 divide-y divide-line">
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
        <p className="mt-3 flex items-start gap-2 text-[13px] leading-relaxed text-suspicious-ink">
          <TriangleAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden /> {t("emPassFreemail")}
        </p>
      )}
    </Section>
  );
}

function UnicodeCard({ findings }: { findings: UnicodeFinding[] }) {
  const { t } = useLang();
  return (
    <Section title={t("emUnicodeTitle")} icon={ScanEye} titleClass="text-scam-ink">
      <p className="text-[14px] leading-relaxed text-ink-soft">{t("emUnicodeIntro")}</p>
      <ul className="mt-3 space-y-2">
        {uniqueFindings(findings)
          .slice(0, 12)
          .map((f, i) => (
            <li key={`${f.where}-${i}`} className="rounded-control bg-muted p-3">
              <p className="flex flex-wrap items-center gap-1.5 text-[12px] font-semibold text-ink-soft">
                <span>{WHERE_LABEL[f.where] ? t(WHERE_LABEL[f.where]) : f.where}</span>
                <span aria-hidden>·</span>
                <span className="text-scam-ink">{KIND_LABEL[f.kind] ? t(KIND_LABEL[f.kind]) : f.kind}</span>
              </p>
              <p dir="ltr" className="mt-1 break-all font-mono text-[14px] font-semibold text-ink">
                {f.sample_escaped}
              </p>
              {f.skeleton && f.skeleton !== f.sample_escaped && (
                <p className="mt-1 text-[13px] text-ink-soft">
                  {t("emImitates")}:{" "}
                  <span dir="ltr" className="font-mono font-semibold text-ink">
                    {f.skeleton}
                  </span>
                </p>
              )}
            </li>
          ))}
      </ul>
    </Section>
  );
}

/** A link row: an email link, or a link found in a pasted message (no shown text, never "unwrapped"). */
type LinkRow = Pick<EmailLink, "url" | "domain" | "verdict" | "risk_score"> &
  Partial<Pick<EmailLink, "display_text" | "text_mismatch" | "unwrapped_from">> & { official?: boolean };

/** No link here is ever clickable: the citizen sees where it would go, defanged, and its scan verdict. */
function LinksCard({ links, title = "emLinksTitle" }: { links: LinkRow[]; title?: DictKey }) {
  const { t } = useLang();
  const shown = [...links]
    .sort((a, b) => Number(b.text_mismatch) - Number(a.text_mismatch) || (b.risk_score ?? -1) - (a.risk_score ?? -1))
    .slice(0, MAX_LINKS_SHOWN);
  return (
    <Section title={t(title)} icon={Link2Off}>
      <ul className="space-y-2">
        {shown.map((l, i) => (
          <li key={`${l.url}-${i}`} className="rounded-control bg-muted p-3">
            <div className="flex items-start justify-between gap-2">
              <dl className="min-w-0 space-y-1 text-[13px]">
                {l.display_text && (
                  <div className="flex gap-1.5">
                    <dt className="shrink-0 font-semibold text-ink-soft">{t("emLinkShows")}:</dt>
                    <dd dir="auto" className="min-w-0 truncate text-ink">
                      {visible(l.display_text)}
                    </dd>
                  </div>
                )}
                <div className="flex gap-1.5">
                  <dt className="shrink-0 font-semibold text-ink-soft">{t("emLinkOpens")}:</dt>
                  <dd dir="ltr" className="min-w-0 truncate font-mono font-semibold text-ink">
                    {l.domain ? defang(l.domain) : defang(l.url)}
                  </dd>
                </div>
              </dl>
              <span className={`shrink-0 ${l.official ? "chip chip-safe" : l.verdict ? TONE_CHIP[toneOf(l.verdict)] : "chip"}`}>
                {l.official && <BadgeCheck className="size-3.5" aria-hidden />}
                {l.official
                  ? t("officialSite")
                  : l.verdict
                    ? `${VERDICT_LABEL[l.verdict] ? t(VERDICT_LABEL[l.verdict]) : l.verdict}${l.risk_score !== null ? ` · ${l.risk_score}` : ""}`
                    : t("emLinkNotScanned")}
              </span>
            </div>
            {(l.text_mismatch || l.unwrapped_from) && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {l.text_mismatch && (
                  <span className="chip chip-scam">
                    <TriangleAlert className="size-3.5" aria-hidden /> {t("emLinkMismatch")}
                  </span>
                )}
                {l.unwrapped_from && (
                  <span className="chip">
                    <EyeOff className="size-3.5" aria-hidden /> {t("emLinkUnwrapped")}
                  </span>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-3 flex items-center gap-1.5 text-[13px] text-ink-soft">
        <ShieldCheck className="size-3.5 shrink-0" aria-hidden /> {t("emLinksDisabled")}
        {links.length > MAX_LINKS_SHOWN && (
          <span>
            {" "}
            · +{links.length - MAX_LINKS_SHOWN} {t("emLinksMore")}
          </span>
        )}
      </p>
    </Section>
  );
}

const PHONE_STATUS: Record<MessagePhone["status"], { key: DictKey; chip: string }> = {
  official: { key: "phOfficial", chip: "chip chip-safe" },
  unofficial: { key: "phUnofficial", chip: "chip chip-suspicious" },
  mobile_for_institution: { key: "phMobile", chip: "chip chip-scam" },
  foreign_for_institution: { key: "phForeign", chip: "chip chip-scam" },
  linked_to_scam: { key: "phLinked", chip: "chip chip-scam" },
  unknown: { key: "phUnknown", chip: "chip" },
};

/** The sender and every phone number found in a pasted message, each with its official-number check. */
function MessageNumbersCard({ message }: { message: MessageDetails }) {
  const { t } = useLang();
  const sender = message.sender;
  const rows = message.phones;
  if (!sender && rows.length === 0) return null;
  const senderStatus = sender?.status ? PHONE_STATUS[sender.status] : null;
  return (
    <Section title={t("msgNumbersTitle")} icon={PhoneCall}>
      <ul className="-my-2 divide-y divide-line">
        {sender && (
          <li className="flex items-center justify-between gap-2 py-2.5 text-[14px]">
            <span className="min-w-0">
              <span className="font-semibold text-ink-soft">{t("msgSenderRow")}: </span>
              <span dir="ltr" className="font-mono font-semibold text-ink">
                {visible(sender.value)}
              </span>
            </span>
            {senderStatus && <span className={`shrink-0 ${senderStatus.chip}`}>{t(senderStatus.key)}</span>}
          </li>
        )}
        {rows.map((p, i) => {
          const st = PHONE_STATUS[p.status] ?? PHONE_STATUS.unknown;
          return (
            <li key={`${p.masked}-${i}`} className="flex items-center justify-between gap-2 py-2.5 text-[14px]">
              <span dir="ltr" className="min-w-0 truncate font-mono font-semibold tabular-nums text-ink">
                {p.e164 ?? p.masked}
              </span>
              <span className={`shrink-0 ${st.chip}`}>{t(st.key)}</span>
            </li>
          );
        })}
      </ul>
      {sender?.type === "alphanumeric" && (
        <p className="mt-3 flex items-start gap-1.5 text-[13px] text-ink-soft">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden /> {t("msgSenderIdNote")}
        </p>
      )}
    </Section>
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
    <Section title={t("emAttachTitle")} icon={Paperclip}>
      <ul className="space-y-2">
        {attachments.slice(0, 20).map((a, i) => (
          <li key={`${a.name}-${i}`} className={`flex items-start gap-3 rounded-control p-3 ${a.risky ? "bg-scam-soft" : "bg-muted"}`}>
            <FileText className={`mt-0.5 size-4 shrink-0 ${a.risky ? "text-scam-ink" : "text-ink-soft"}`} aria-hidden />
            <div className="min-w-0 flex-1">
              <p dir="ltr" className="truncate text-start font-mono text-[14px] font-semibold text-ink">
                {visible(a.name) || "—"}
              </p>
              {a.risky && (
                <p className="mt-0.5 text-[13px] font-semibold text-scam-ink">
                  {t("emAttachRisky")}
                  {a.reason ? ` · ${a.reason}` : ""}
                </p>
              )}
            </div>
            <span className="shrink-0 text-[13px] tabular-nums text-ink-soft">{formatBytes(a.size)}</span>
          </li>
        ))}
      </ul>
    </Section>
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
    <Section title={t("emCampaignTitle")} icon={Megaphone}>
      <ul className="space-y-4">
        {campaigns.map((c) => {
          const sources = (refs[c.id] ?? []).map((r) => ({ ...r, href: safeHttps(r.url) })).filter((r) => r.href);
          return (
            <li key={c.id}>
              <p className="text-[17px] font-semibold leading-snug text-ink">{lang === "ar" ? c.title_ar || c.title_en : c.title_en}</p>
              <p className="mt-0.5 text-[13px] font-medium text-ink-soft">{t(c.match === "ioc" ? "emCampaignIoc" : "emCampaignLure")}</p>
              {c.matched.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {c.matched.slice(0, 8).map((m) => (
                    <span key={m} dir="auto" className="chip font-medium">
                      {c.match === "ioc" ? defang(m) : m}
                    </span>
                  ))}
                </div>
              )}
              {sources.length > 0 && (
                <p className="mt-2 text-[13px] text-ink-soft">
                  <span className="font-semibold">{t("emCampaignSources")}: </span>
                  {sources.slice(0, 4).map((r, i) => (
                    <span key={`${r.href}-${i}`}>
                      {i > 0 && " · "}
                      <a
                        href={r.href ?? undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-ink underline underline-offset-2"
                      >
                        {r.title || r.source_id} <ExternalLink className="size-3" aria-hidden />
                      </a>
                    </span>
                  ))}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </Section>
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
    <Section title={t("emModelTitle")} icon={BrainCircuit}>
      <p className="text-[15px] font-semibold text-ink">{line}</p>
      <p className="mt-1 text-[13px] leading-relaxed text-ink-soft">{t("emModelAsk")}</p>
      <div className="mt-3 grid grid-cols-2 gap-2">
        {(
          [
            ["scam", "emLabelScam", ThumbsDown, "border-transparent bg-scam text-on-scam hover:bg-scam"],
            ["ham", "emLabelHam", ThumbsUp, "border-transparent bg-safe text-on-safe hover:bg-safe"],
          ] as const
        ).map(([label, key, Icon, activeStyle]) => (
          <button
            key={label}
            type="button"
            disabled={state === "saving"}
            onClick={() => void send(label)}
            aria-pressed={chosen === label && state === "saved"}
            className={`btn-secondary px-3 ${chosen === label && state === "saved" ? activeStyle : ""}`}
          >
            <Icon className="size-4" aria-hidden /> {t(key)}
          </button>
        ))}
      </div>
      <div aria-live="polite">
        {state === "saved" && (
          <p className="mt-2 flex items-center gap-1.5 text-[13px] font-semibold text-ink">
            <CircleCheck className="size-3.5" aria-hidden /> {t("emLabelSaved")}
          </p>
        )}
        {state === "failed" && (
          <p className="mt-2 flex items-center gap-1.5 text-[13px] font-semibold text-ink">
            <Info className="size-3.5" aria-hidden /> {t("emLabelFailed")}
          </p>
        )}
      </div>
      <a
        href={emailModelDownloadUrl()}
        download="saqr-my-model.json"
        className="mt-3 inline-flex min-h-11 items-center gap-1.5 text-[13px] font-semibold text-ink underline underline-offset-2"
      >
        <Download className="size-3.5" aria-hidden /> {t("emModelDownload")}
      </a>
    </Section>
  );
}

function LlmNote({ email }: { email: EmailDetails }) {
  const { t } = useLang();
  if (email.userLlmError) {
    return (
      <p className="flex items-start gap-2 rounded-control bg-muted p-3 text-[14px] text-ink">
        <Bot className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>
          {t("llmFailed")} <span className="text-[13px] text-ink-soft">({email.userLlmError})</span>
        </span>
      </p>
    );
  }
  if (!email.userLlmHost) return null;
  return (
    <p className="flex items-center gap-2 rounded-control bg-muted p-3 text-[14px] text-ink-soft">
      <Bot className="size-4 shrink-0" aria-hidden /> {t("llmUsed")}{" "}
      <span dir="ltr" className="font-mono text-[13px]">
        ({email.userLlmHost})
      </span>
    </p>
  );
}

function AiNotes({ notes }: { notes: string[] }) {
  const { t } = useLang();
  return (
    <Section title={t("emAiNotes")} icon={Sparkles}>
      <ul className="space-y-1.5">
        {notes.slice(0, 6).map((n, i) => (
          <li key={i} className="flex gap-2 text-[15px] text-ink" dir="auto">
            <span className="mt-2 size-1.5 shrink-0 rounded-full bg-ink-soft" aria-hidden />
            <span>{n}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

export function stripBullets(text: string): string {
  return text
    .split(/\n\s*\n/)
    .filter((p) => !/^\s*(red flags|علامات الخطر)\s*:/i.test(p) && !/^\s*•/.test(p))
    .join("\n\n")
    .trim();
}

function ScanningView({ target, interception, kind }: { target: string; interception: InterceptionChannel; kind?: ScanVerdict["kind"] }) {
  const { t } = useLang();
  const [step, setStep] = useState(0);
  const steps = scanSteps(kind);
  useEffect(() => {
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, steps.length - 1)), kind === "email" ? 520 : 650);
    return () => window.clearInterval(id);
  }, [steps.length, kind]);
  const Icon = kind === "email" ? Mail : kind === "message" ? MessageSquareText : ShieldCheck;

  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-canvas px-6 py-16 text-ink" data-testid="fullscreen-scanning">
      <div className="relative grid size-44 place-items-center overflow-hidden rounded-full">
        {[0, 1, 2].map((i) => (
          <span key={i} className="absolute inset-0 rounded-full border border-line" style={{ transform: `scale(${0.45 + i * 0.27})` }} />
        ))}
        <span className="absolute inset-0 animate-sweep rounded-full bg-[conic-gradient(from_0deg,color-mix(in_oklab,var(--color-ink)_22%,transparent),transparent_28%)]" />
        <div className="relative grid size-16 place-items-center rounded-card border border-line bg-surface shadow-card">
          <Icon className="size-8" aria-hidden />
        </div>
      </div>
      <p className="chip mt-6">{t(CHANNEL_KEY[interception])}</p>
      <h2 className="shimmer-text mt-3 text-center text-[24px] font-bold tracking-tight">{t(scanTitle(kind))}</h2>
      <p className="mt-2 max-w-xs truncate text-center font-mono text-[13px] text-ink-soft" dir="ltr">
        {visible(target)}
      </p>
      <ul className="mt-8 w-full max-w-sm space-y-2.5" aria-live="polite">
        {steps.map((key, i) => (
          <li key={key} className={`flex items-center gap-3 text-[15px] transition-opacity ${i <= step ? "opacity-100" : "opacity-40"}`}>
            {i < step ? (
              <CircleCheck className="size-5 shrink-0" aria-hidden />
            ) : i === step ? (
              <RefreshCw className="size-5 shrink-0 animate-spin" aria-hidden />
            ) : (
              <span className="size-5 shrink-0 rounded-full border border-line" aria-hidden />
            )}
            <span>{t(key)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

type ReportState = "closed" | "open" | "sending" | "sent" | "already" | "error";

/** "Report a false alarm": a quiet link that opens a short optional note, then a thank-you line. */
export function FalseAlarmReport({ scanId, compact = false }: { scanId: string; compact?: boolean }) {
  const { t } = useLang();
  const [state, setState] = useState<ReportState>("closed");
  const [note, setNote] = useState("");
  const [error, setError] = useState<DictKey>("faFailed");

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

  if (!scanId) return null;
  return (
    <div aria-live="polite" data-testid="false-alarm">
      {state === "closed" && (
        <button
          type="button"
          onClick={() => setState("open")}
          data-testid="false-alarm-open"
          className={`inline-flex min-h-11 items-center gap-1.5 text-[14px] font-semibold text-ink-soft underline-offset-2 hover:text-ink hover:underline ${compact ? "" : "-ms-0.5"}`}
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
          <label htmlFor={`fa-note-${scanId}-${compact ? "c" : "f"}`} className="block text-[13px] font-semibold text-ink">
            {t("faNoteLabel")}
          </label>
          <textarea
            id={`fa-note-${scanId}-${compact ? "c" : "f"}`}
            value={note}
            onChange={(e) => setNote(e.target.value.slice(0, FALSE_ALARM_NOTE_MAX))}
            maxLength={FALSE_ALARM_NOTE_MAX}
            rows={2}
            dir="auto"
            placeholder={t("faNotePlaceholder")}
            className="field resize-none py-2.5"
          />
          <p className="flex justify-between gap-3 text-[12px] text-ink-soft">
            <span>{t("faSentWhat")}</span>
            <span className="shrink-0 tabular-nums" dir="ltr">
              {note.length}/{FALSE_ALARM_NOTE_MAX}
            </span>
          </p>
          {state === "error" && (
            <p className="flex items-center gap-1.5 text-[13px] font-semibold text-ink">
              <Info className="size-3.5 shrink-0" aria-hidden /> {t(error)}
            </p>
          )}
          <div className="flex flex-wrap gap-2">
            <button type="submit" disabled={state === "sending"} className="btn-secondary min-h-11 px-4 text-[14px]" data-testid="false-alarm-send">
              {t(state === "sending" ? "faSending" : "faSend")}
            </button>
            <button type="button" onClick={() => setState("closed")} className="min-h-11 rounded-control px-3 text-[14px] font-semibold text-ink-soft hover:text-ink">
              {t("faCancel")}
            </button>
          </div>
        </form>
      )}
      {(state === "sent" || state === "already") && (
        <p className="flex items-center gap-1.5 py-2 text-[14px] font-semibold text-ink">
          <CircleCheck className="size-4 shrink-0" aria-hidden /> {t(state === "sent" ? "faThanks" : "faAlready")}
        </p>
      )}
    </div>
  );
}

/** One-line privacy note, plus (for warnings only) the false-alarm report. */
function PrivacyAndFeedback({ scanId, canReport }: { scanId: string; canReport: boolean }) {
  const { t } = useLang();
  return (
    <section className="space-y-2 border-t border-line pt-4">
      <p className="flex items-start gap-2 text-[13px] leading-relaxed text-ink-soft">
        <Lock className="mt-0.5 size-3.5 shrink-0" aria-hidden /> {t("privacyLine")}
      </p>
      {canReport && <FalseAlarmReport scanId={scanId} />}
    </section>
  );
}

const HEADER_ICON: Record<Tone, typeof ShieldCheck> = { scam: ShieldAlert, suspicious: TriangleAlert, safe: ShieldCheck };

/** The full report. `embedded` = inside the "Full report" drawer (the drawer owns the close button). */
export function ResultView({ result, onClose, embedded = false }: { result: ScanVerdict; onClose: () => void; embedded?: boolean }) {
  const { t, lang } = useLang();
  const [showOther, setShowOther] = useState(false);
  const tone = toneOf(result.verdict);
  const entity = (lang === "ar" ? result.entityAr : result.entityEn) ?? result.entityEn ?? t("unknownEntity");
  const primary = stripBullets(lang === "ar" ? result.explanationAr : result.explanationEn);
  const secondary = stripBullets(lang === "ar" ? result.explanationEn : result.explanationAr);
  const official = result.officialDomains[0];
  const syndicate = lang === "ar" ? result.syndicateAr ?? result.syndicateEn : result.syndicateEn;
  const email = result.kind === "email" ? result.email ?? null : null;
  const message = result.kind === "message" ? result.message ?? null : null;
  const verified = isVerifiedOfficial(result);
  const title = email
    ? t(tone === "scam" ? "emBlockedTitle" : tone === "suspicious" ? "emSuspiciousTitle" : "emSafeTitle")
    : message
      ? t(tone === "scam" ? "msgBlockedTitle" : tone === "suspicious" ? "msgSuspiciousTitle" : "msgSafeTitle")
      : t(tone === "scam" ? "blockedTitle" : tone === "suspicious" ? "suspiciousTitle" : "safeTitle");
  const HeaderIcon = HEADER_ICON[tone];

  return (
    <div className={embedded ? "" : "min-h-full bg-canvas"} data-testid="verdict-report">
      <div className={embedded ? "space-y-4" : "mx-auto max-w-2xl space-y-4 px-4 pb-10 pt-4 sm:pt-8"}>
        {/* Verdict header */}
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="card p-5"
        >
          <div className="flex items-start justify-between gap-3">
            <span className={TONE_CHIP[tone]}>
              <HeaderIcon className="size-3.5" aria-hidden /> {VERDICT_LABEL[result.verdict] ? t(VERDICT_LABEL[result.verdict]) : result.verdict}
            </span>
            {!embedded && (
              <button
                type="button"
                onClick={onClose}
                aria-label={t("close")}
                data-testid="verdict-close"
                className="-me-2 -mt-2 grid size-12 shrink-0 place-items-center rounded-full text-ink-soft hover:bg-muted hover:text-ink"
              >
                <X className="size-5" aria-hidden />
              </button>
            )}
          </div>
          <h2 className={`mt-3 text-[24px] font-bold leading-tight tracking-tight sm:text-[28px] ${TONE_TEXT[tone]}`}>{title}</h2>
          <p className="mt-1 text-[14px] text-ink-soft">
            {email || message ? t(email ? "emCheckedBy" : "msgCheckedBy") : tone !== "safe" ? t("blockedBy") : null}
          </p>
          <p className="mt-2 truncate font-mono text-[13px] text-ink-soft" dir="ltr">
            {visible(result.kind === "url" ? defang(result.target) : result.target)}
          </p>
          <div className="mt-4 flex items-end gap-4">
            <p className="shrink-0 text-ink">
              <span className="text-[40px] font-bold leading-none tabular-nums">{result.riskScore}</span>
              <span className="ms-1 text-[15px] text-ink-soft tabular-nums">/ 100</span>
            </p>
            <RiskMeter score={result.riskScore} className="min-w-0 flex-1 pb-0.5" />
          </div>
          {verified && (
            <p className="mt-4 flex items-center gap-2 text-[15px] font-semibold text-safe-ink">
              <BadgeCheck className="size-4 shrink-0" aria-hidden /> {message ? t("msgVerified") : t("vcVerified")}
            </p>
          )}
          <p className="mt-4 border-t border-line pt-3 text-[13px] text-ink-soft">
            <span className="font-semibold text-ink">{t("syncedBadge")}</span>
            <br />
            <span dir="ltr" className="font-mono">
              {t("caseId")} {result.scanId} · {new Date().toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE")}
            </span>{" "}
            · {t("detectedVia")}: {t(CHANNEL_KEY[result.interception])}
          </p>
        </motion.section>

        {tone !== "safe" && (
          <Section title={t("impersonating")} icon={ShieldAlert}>
            <p className="text-[19px] font-semibold text-scam-ink">{entity}</p>
            {official && (
              <p className="mt-3 border-t border-line pt-3 text-[14px] text-ink-soft">
                {t("officialSite")}:{" "}
                <span className="inline-flex items-center gap-1.5 font-semibold text-safe-ink" dir="ltr">
                  <ShieldCheck className="size-4" aria-hidden /> {official}
                </span>
              </p>
            )}
          </Section>
        )}

        {email && <SenderCard email={email} />}

        {result.harvested.length > 0 && (
          <Section title={t("wantsYour")} icon={KeyRound} titleClass="text-scam-ink">
            <div className="flex flex-wrap gap-2">
              {result.harvested
                .filter((h) => HARVEST_LABELS[h])
                .map((h) => {
                  const Icon = HARVEST_LABELS[h].icon;
                  return (
                    <span key={h} className="chip chip-scam">
                      <Icon className="size-3.5" aria-hidden /> {HARVEST_LABELS[h][lang]}
                    </span>
                  );
                })}
            </div>
          </Section>
        )}

        {primary && (
          <motion.section
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.2 }}
            className="card p-4 sm:p-5"
          >
            <div className="flex items-center justify-between gap-2">
              <h3 className="label-caps">{t(tone === "safe" ? "whySafe" : "whyDangerous")}</h3>
              <button
                type="button"
                onClick={() => setShowOther((s) => !s)}
                aria-expanded={showOther}
                className="inline-flex min-h-10 items-center gap-1.5 rounded-full px-3 text-[13px] font-semibold text-ink-soft hover:bg-muted hover:text-ink"
              >
                <Languages className="size-3.5" aria-hidden /> {t("otherLanguage")}
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
                  lang={lang === "ar" ? "en" : "ar"}
                  className="mt-3 overflow-hidden whitespace-pre-line border-t border-line pt-3 text-[15px] leading-relaxed text-ink-soft"
                >
                  {secondary}
                </motion.p>
              )}
            </AnimatePresence>
          </motion.section>
        )}

        {email && email.unicode.length > 0 && <UnicodeCard findings={email.unicode} />}
        {email && email.campaigns.length > 0 && <CampaignCard campaigns={email.campaigns} />}

        {result.redFlags.length > 0 && (
          <Section title={t("redFlags")} icon={TriangleAlert}>
            <ul className="-my-2 divide-y divide-line">
              {[...result.redFlags]
                .sort((a, b) => b.points - a.points)
                .map((f, i) => (
                  <li key={`${f.code}-${i}`} className="flex gap-3 py-2.5">
                    <span className={`h-fit shrink-0 ${SEVERITY_CHIP[f.severity]}`}>
                      {SEVERITY_LABEL[f.severity] ? t(SEVERITY_LABEL[f.severity]) : f.severity}
                    </span>
                    <span className="text-[15px] leading-snug text-ink">{lang === "ar" ? f.ar : f.en}</span>
                  </li>
                ))}
            </ul>
          </Section>
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

        {message && (
          <>
            {message.links.length > 0 && <LinksCard links={message.links} title="msgLinksTitle" />}
            <MessageNumbersCard message={message} />
          </>
        )}

        {tone !== "safe" && result.riskScore >= 60 && <XAlertPrompt warning={warningFromVerdict(result)} />}

        {email && <PersonalModelCard scanId={result.scanId} model={email.userModel} />}

        {(email || message) && tone === "safe" && (
          <p className="flex items-start gap-2 rounded-control bg-muted p-3 text-[14px] text-ink-soft">
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden /> {t(email ? "emSafeNote" : "msgSafeNote")}
          </p>
        )}

        {(syndicate || result.ip || result.domainAgeHours !== null || result.cloaking) && (
          <section className="card divide-y divide-line px-4 sm:px-5">
            {syndicate && (
              <div className="py-3.5">
                <p className="label-caps flex items-center gap-2">
                  <Network className="size-4" aria-hidden /> {t("syndicateLink")}
                </p>
                <p className="mt-1 text-[17px] font-semibold text-scam-ink">{syndicate}</p>
              </div>
            )}
            {result.domainAgeHours !== null && (
              <div className="flex items-center gap-3 py-3.5">
                <Clock className="size-5 shrink-0 text-ink-soft" aria-hidden />
                <div>
                  <p className="text-[13px] text-ink-soft">{t("registered")}</p>
                  <p className="font-semibold tabular-nums">
                    {Math.round(result.domainAgeHours)} {t("hoursAgo")}
                  </p>
                </div>
              </div>
            )}
            {result.ip && (
              <div className="flex items-center gap-3 py-3.5">
                <Server className="size-5 shrink-0 text-ink-soft" aria-hidden />
                <div>
                  <p className="text-[13px] text-ink-soft">{t("hostedOn")}</p>
                  <p className="font-mono font-semibold" dir="ltr">
                    {result.ip}
                  </p>
                </div>
              </div>
            )}
            {result.cloaking && (
              <div className="flex items-center gap-3 py-3.5">
                <EyeOff className="size-5 shrink-0 text-suspicious-ink" aria-hidden />
                <p className="font-semibold">{t("cloaking")}</p>
              </div>
            )}
          </section>
        )}

        {result.screenshot && (
          <Section title={t("evidence")} icon={ScanEye}>
            <div className="relative overflow-hidden rounded-control border border-line">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`data:image/jpeg;base64,${result.screenshot}`}
                alt="Sandbox screenshot of the blocked page"
                className="max-h-80 w-full object-cover object-top opacity-90 blur-[1px] grayscale-[30%]"
              />
              <div className="absolute inset-0 grid place-items-center">
                <span className="rotate-[-12deg] rounded-control border-4 border-scam bg-surface px-4 py-1 text-2xl font-black tracking-widest text-scam-ink">
                  BLOCKED
                </span>
              </div>
            </div>
          </Section>
        )}

        <PrivacyAndFeedback key={result.scanId} scanId={result.scanId} canReport={tone !== "safe"} />

        <div className={`sticky bottom-0 space-y-2 bg-canvas pb-4 pt-3 ${embedded ? "-mx-4 px-4 sm:-mx-5 sm:px-5" : "-mx-4 px-4"}`}>
          <button type="button" onClick={onClose} className="btn-primary w-full" data-testid="verdict-back">
            <ArrowLeft className="size-5 rtl:rotate-180" aria-hidden /> {t("backToSafety")}
          </button>
          <div className="grid grid-cols-2 gap-2">
            {tone === "safe" && (email || message) ? (
              official ? (
                <a href={`https://${official}`} target="_blank" rel="noopener noreferrer" className="btn-secondary col-span-2">
                  <BadgeCheck className="size-4 text-safe-ink" aria-hidden /> {t("goOfficial")}
                </a>
              ) : null
            ) : tone === "safe" ? (
              <a href={official ? `https://${official}` : "#"} target="_blank" rel="noopener noreferrer" className="btn-secondary col-span-2">
                <ExternalLink className="size-4" aria-hidden /> {t("continueSite")}
              </a>
            ) : (
              <>
                {official && (
                  <a href={`https://${official}`} target="_blank" rel="noopener noreferrer" className="btn-secondary px-3">
                    <BadgeCheck className="size-4 shrink-0 text-safe-ink" aria-hidden /> {t("goOfficial")}
                  </a>
                )}
                <a href="tel:8002626" className={`btn-secondary px-3 ${official ? "" : "col-span-2"}`}>
                  <PhoneCall className="size-4 shrink-0" aria-hidden /> {t("callAman")}
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
    <div className="flex min-h-full flex-col items-center justify-center bg-canvas px-6 text-center text-ink">
      <Info className="size-12 text-ink-soft" aria-hidden />
      <h2 className="mt-4 text-[24px] font-bold">{t("scanFailed")}</h2>
      <p className="mt-2 max-w-sm text-[15px] text-ink-soft">{message}</p>
      <div className="mt-6 flex gap-3">
        <button type="button" onClick={onRetry} className="btn-primary">
          {t("retry")}
        </button>
        <button type="button" onClick={onClose} className="btn-secondary">
          {t("close")}
        </button>
      </div>
    </div>
  );
}

/** Full-screen block page (share target, scam-alert notification, DNS block). */
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
          aria-label={state.status === "done" ? t_verdictAria(state.result) : undefined}
          data-testid="verdict-fullscreen"
          initial={{ y: "100%" }}
          animate={{ y: 0 }}
          exit={{ y: "100%" }}
          transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
          className="fixed inset-0 z-50 overflow-y-auto overscroll-contain bg-canvas no-scrollbar"
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={state.status}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.2 }}
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

/** Dialog name for screen readers: the verdict word + the target (English; the content itself is localised). */
function t_verdictAria(r: ScanVerdict): string {
  return `${r.verdict} · ${r.target}`;
}
