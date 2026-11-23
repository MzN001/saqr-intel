/**
 * Where the browser sends API calls. Empty locally (relative `/api/...`, proxied by next.config);
 * on Vercel set NEXT_PUBLIC_API_URL to the public backend (e.g. the Cloudflare tunnel URL).
 */
export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(/[﻿\s]+/g, "").replace(/\/+$/, "");

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`;
}

/** WebSocket address of the live feed (`/ws/live`). */
export function getWsUrl(): string {
  if (API_BASE_URL.startsWith("https://")) return `${API_BASE_URL.replace("https://", "wss://")}/ws/live`;
  if (API_BASE_URL.startsWith("http://")) return `${API_BASE_URL.replace("http://", "ws://")}/ws/live`;
  if (typeof window !== "undefined") {
    // Same origin: the Next dev server proxies /ws to the backend (also works over LAN IPs and tunnels).
    return `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws/live`;
  }
  return "ws://127.0.0.1:8000/ws/live";
}

export type InterceptionChannel =
  | "MOBILE_OS_SHARE_SHEET"
  | "AUTO_TELECOM_DNS"
  | "AUTO_SMS_GUARD"
  | "CITIZEN_MANUAL_CHECK"
  | "PC_BROWSER_EXTENSION"
  | "DIRECT_API"
  | "MANUAL";

export type VerdictLabel = "SAFE" | "SUSPICIOUS" | "HIGH-RISK SCAM";

export interface RedFlag {
  code: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  points: number;
  en: string;
  ar: string;
  /** Email flags only. */
  strength?: "strong" | "weak" | "info";
  evidence?: string | null;
}

interface SyndicateBrief {
  id: string;
  name: string;
  name_ar?: string | null;
  domains?: string[];
  ip_addresses?: string[];
}

interface UrlScanResponse {
  scan_id: string;
  kind: "url";
  domain: string;
  input_url: string;
  verdict: VerdictLabel;
  risk_score: number;
  impersonated_entity: string | null;
  impersonated_entity_ar: string | null;
  official_domains: string[];
  citizen_explanation_en: string;
  citizen_explanation_ar: string;
  red_flags: RedFlag[];
  syndicate: SyndicateBrief | null;
  screenshot_base64?: string | null;
  analyzer?: { engine: string };
  technical_indicators: {
    ip_addresses?: string[];
    harvested_fields?: string[];
    ssl_issuer?: string | null;
    domain_age_hours?: number | null;
    cloaking?: { detected?: boolean } | null;
  };
}

interface MapsScanResponse {
  scan_id: string;
  kind: "maps";
  verdict: VerdictLabel;
  risk_score: number;
  impersonated_entity: string | null;
  impersonated_entity_ar: string | null;
  official_domains: string[];
  official_phones: string[];
  citizen_explanation_en: string;
  citizen_explanation_ar: string;
  red_flags: RedFlag[];
  syndicate: SyndicateBrief | null;
  listing: {
    name: string | null;
    address: string | null;
    website_domain: string | null;
    phone: string | null;
    lat: number | null;
    lng: number | null;
  };
}

export interface ScanVerdict {
  kind: "url" | "maps" | "email";
  scanId: string;
  target: string;
  /** The website domain behind the scam (used, defanged, in community warnings). */
  scamDomain: string | null;
  riskScore: number;
  verdict: VerdictLabel;
  entityEn: string | null;
  entityAr: string | null;
  officialDomains: string[];
  officialPhones: string[];
  explanationEn: string;
  explanationAr: string;
  redFlags: RedFlag[];
  harvested: string[];
  ip: string | null;
  sslIssuer: string | null;
  domainAgeHours: number | null;
  cloaking: boolean;
  screenshot: string | null;
  syndicateEn: string | null;
  syndicateAr: string | null;
  engine: string;
  interception: InterceptionChannel;
  /** Only for kind "email": sender, authentication, links, attachments, campaigns, personal model. */
  email?: EmailDetails;
}

export interface AwarenessWave {
  entity: string;
  scans: number;
  ct_detections: number;
  citizen_reports: number;
  domains: string[];
  top_channels: string[];
  score: number;
  target_areas?: string[];
}

export interface AwarenessAlert {
  status: "active_wave" | "no_active_wave";
  generated_at: string;
  window_hours?: number;
  severity?: "HIGH" | "MEDIUM" | "LOW";
  trending_entity?: string;
  wave?: AwarenessWave;
  other_waves?: AwarenessWave[];
  hashtags?: string[];
  engine?: string;
  title_en?: string;
  title_ar?: string;
  post_en?: string;
  post_ar?: string;
  x_post_en?: string;
  x_post_ar?: string;
  safety_tips_en?: string[];
  safety_tips_ar?: string[];
}

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

/** FastAPI sends `detail` as a string, or as a list of validation errors ({loc, msg}). */
function errorDetail(body: unknown, status: number): string {
  const detail = typeof body === "object" && body !== null && "detail" in body ? (body as { detail: unknown }).detail : null;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msgs = detail
      .map((d) => (typeof d === "object" && d !== null && "msg" in d ? String((d as { msg: unknown }).msg) : null))
      .filter(Boolean);
    if (msgs.length) return msgs.join("; ");
  }
  return `Request failed (${status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(apiUrl(path), {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
      cache: "no-store",
    });
  } catch {
    throw new ApiError("Can't reach the SAQR-INTEL server right now (it may be waking up). Please try again in 30 seconds.", 0);
  }
  const ct = res.headers.get("content-type") ?? "";
  const body: unknown = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) {
    throw new ApiError(errorDetail(body, res.status), res.status);
  }
  return body as T;
}

function fromUrlScan(r: UrlScanResponse, interception: InterceptionChannel): ScanVerdict {
  const ti = r.technical_indicators ?? {};
  return {
    kind: "url",
    scanId: r.scan_id,
    target: r.domain,
    scamDomain: r.domain,
    riskScore: r.risk_score,
    verdict: r.verdict,
    entityEn: r.impersonated_entity,
    entityAr: r.impersonated_entity_ar,
    officialDomains: r.official_domains ?? [],
    officialPhones: [],
    explanationEn: r.citizen_explanation_en,
    explanationAr: r.citizen_explanation_ar,
    redFlags: (r.red_flags ?? []).filter((f) => f.points > 0),
    harvested: ti.harvested_fields ?? [],
    ip: ti.ip_addresses?.[0] ?? null,
    sslIssuer: ti.ssl_issuer ?? null,
    domainAgeHours: ti.domain_age_hours ?? null,
    cloaking: Boolean(ti.cloaking?.detected),
    screenshot: r.screenshot_base64 ?? null,
    syndicateEn: r.syndicate?.name ?? null,
    syndicateAr: r.syndicate?.name_ar ?? null,
    engine: r.analyzer?.engine ?? "rules",
    interception,
  };
}

function fromMapsScan(r: MapsScanResponse, interception: InterceptionChannel): ScanVerdict {
  return {
    kind: "maps",
    scanId: r.scan_id,
    target: r.listing.name ?? r.listing.website_domain ?? "Google Maps listing",
    scamDomain: r.listing.website_domain,
    riskScore: r.risk_score,
    verdict: r.verdict,
    entityEn: r.impersonated_entity,
    entityAr: r.impersonated_entity_ar,
    officialDomains: r.official_domains ?? [],
    officialPhones: r.official_phones ?? [],
    explanationEn: r.citizen_explanation_en,
    explanationAr: r.citizen_explanation_ar,
    redFlags: (r.red_flags ?? []).filter((f) => f.points > 0),
    harvested: [],
    ip: null,
    sslIssuer: null,
    domainAgeHours: null,
    cloaking: false,
    screenshot: null,
    syndicateEn: r.syndicate?.name ?? null,
    syndicateAr: r.syndicate?.name_ar ?? null,
    engine: "rules",
    interception,
  };
}

export async function analyzeUrl(
  url: string,
  interception: InterceptionChannel,
  channel: "web" | "sms" | "social" = "web",
  messageText?: string,
): Promise<ScanVerdict> {
  const r = await request<UrlScanResponse>("/api/analyze-url", {
    method: "POST",
    body: JSON.stringify({
      url,
      channel,
      interception_channel: interception,
      device_profile: "mobile",
      ...(messageText ? { message_text: messageText.slice(0, 4000) } : {}),
    }),
  });
  return fromUrlScan(r, interception);
}

export interface MapsScanInput {
  maps_url?: string;
  business_name?: string;
  website?: string;
  phone?: string;
  lat?: number;
  lng?: number;
}

export async function scanMaps(input: MapsScanInput, interception: InterceptionChannel): Promise<ScanVerdict> {
  const r = await request<MapsScanResponse>("/api/scan-maps", {
    method: "POST",
    body: JSON.stringify({ ...input, interception_channel: interception }),
  });
  return fromMapsScan(r, interception);
}

export interface NextDnsStatus {
  configured: boolean;
  profile_id: string | null;
  synced_domains: number;
  last_sync: string | null;
  last_error: string | null;
}

/** Is SAQR's live feed being pushed to a NextDNS profile (real phone protection)? */
export async function getNextDnsStatus(): Promise<NextDnsStatus> {
  return request<NextDnsStatus>("/api/nextdns-status");
}

// ---------------------------------------------------------------- scam-alert push notifications
export async function getVapidPublicKey(): Promise<string> {
  return (await request<{ publicKey: string }>("/api/push/vapid-public-key")).publicKey;
}

export async function savePushSubscription(subscription: PushSubscriptionJSON, lang: "en" | "ar"): Promise<void> {
  await request("/api/push/subscribe", { method: "POST", body: JSON.stringify({ subscription, lang }) });
}

export async function deletePushSubscription(endpoint: string): Promise<void> {
  await request("/api/push/unsubscribe", { method: "POST", body: JSON.stringify({ endpoint }) });
}

export async function sendTestAlert(endpoint: string): Promise<void> {
  await request("/api/push/test", { method: "POST", body: JSON.stringify({ endpoint }) });
}

/** The verdict a scam-alert notification opens (the domain the phone's DNS shield just blocked). */
export async function getAlertVerdict(domain: string): Promise<ScanVerdict> {
  const r = await request<UrlScanResponse>(`/api/alerts/verdict?domain=${encodeURIComponent(domain)}`);
  return fromUrlScan(r, "AUTO_TELECOM_DNS");
}

export async function getAwareness(params: { entity?: string; useLlm?: boolean } = {}): Promise<AwarenessAlert> {
  const q = new URLSearchParams({ hours: "168" });
  if (params.entity) q.set("entity", params.entity);
  if (params.useLlm === false) q.set("use_llm", "false");
  return request<AwarenessAlert>(`/api/awareness-alert?${q.toString()}`);
}

// ---------------------------------------------------------------- email scanning (POST /api/analyze-email)

export type EmailSource = "text" | "raw" | "eml" | "msg";
export type AuthResult = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "not_checked";

export interface EmailAddressInfo {
  display_name: string;
  address: string;
  domain: string;
  registered_domain: string;
  /** The domain written in its real letters (differs from `domain` when that is punycode "xn--..."). */
  unicode_domain: string;
  is_freemail: boolean;
  is_official: boolean;
}

export interface EmailLink {
  url: string;
  display_text: string;
  domain: string;
  unwrapped_from: string | null;
  text_mismatch: boolean;
  scan_id: string | null;
  risk_score: number | null;
  verdict: VerdictLabel | null;
}

export interface EmailAttachment {
  name: string;
  size: number;
  risky: boolean;
  reason: string | null;
}

export interface UnicodeFinding {
  where: string;
  kind: "punycode" | "mixed_script" | "whole_script_confusable" | "invisible" | "bidi" | "fancy" | string;
  /** The suspicious text with hidden/lookalike characters written as \uXXXX, safe to display. */
  sample_escaped: string;
  /** What the text imitates once lookalike letters are swapped for plain Latin ones. */
  skeleton: string;
}

export interface CampaignMatch {
  id: string;
  title_en: string;
  title_ar: string;
  match: "ioc" | "lure";
  points: number;
  matched: string[];
}

export interface UserModelInfo {
  available: boolean;
  p_scam: number | null;
  labels: number;
  spec: string;
}

export interface EmailAuthentication {
  trusted_authserv: string | null;
  spf: { result: AuthResult; domain: string; client_ip: string; source: string };
  dkim: { domain: string; selector: string; result: AuthResult; aligned: boolean; source: string }[];
  dmarc: {
    result: AuthResult;
    policy: "reject" | "quarantine" | "none" | null;
    alignment: { spf: boolean; dkim: boolean };
    source: string;
  };
  arc: { result: AuthResult; chain_length: number };
}

/** Everything the email verdict screen shows (a subset of the server response). */
export interface EmailDetails {
  source: EmailSource | string;
  subject: string;
  date: string | null;
  hasHeaders: boolean;
  isBulk: boolean;
  from: EmailAddressInfo | null;
  replyTo: EmailAddressInfo | null;
  returnPath: EmailAddressInfo | null;
  bodyExcerpt: string;
  auth: EmailAuthentication | null;
  unicode: UnicodeFinding[];
  links: EmailLink[];
  attachments: EmailAttachment[];
  campaigns: CampaignMatch[];
  userModel: UserModelInfo | null;
  llmRedFlags: string[];
  userLlmHost: string | null;
  userLlmError: string | null;
}

/** The server response of POST /api/analyze-email (tests/fixtures/contract/analyze_email_response.json). */
export interface EmailScanVerdict {
  scan_id: string;
  kind: "email";
  created_at: string;
  target: string;
  domain: null;
  channel: "email";
  interception_channel: string;
  source: EmailSource | string;
  risk_score: number;
  verdict: VerdictLabel;
  impersonated_entity: string | null;
  impersonated_entity_ar: string | null;
  official_domains: string[];
  citizen_explanation_en: string;
  citizen_explanation_ar: string;
  red_flags: RedFlag[];
  llm_red_flags: string[];
  email: {
    subject: string;
    date: string | null;
    has_headers: boolean;
    is_bulk: boolean;
    list_id: string | null;
    to_count: number;
    from: EmailAddressInfo | null;
    reply_to: EmailAddressInfo | null;
    return_path: EmailAddressInfo | null;
    sender: EmailAddressInfo | null;
    body_excerpt: string;
  };
  authentication: EmailAuthentication | null;
  unicode: { findings: UnicodeFinding[] } | null;
  links: EmailLink[];
  attachments: EmailAttachment[];
  campaigns: CampaignMatch[];
  user_model: UserModelInfo | null;
  model_features: number[];
  analyzer: {
    engine: string;
    confidence: number | null;
    user_llm_host: string | null;
    user_llm_error: string | null;
  };
  timings: Record<string, number>;
}

/** A user-supplied OpenAI-compatible endpoint. Sent with one request only; the server never stores it. */
export interface UserLlmConfig {
  base_url: string;
  api_key: string;
  model: string;
}

export interface EmailScanInput {
  source: EmailSource;
  /** Pasted visible text (source "text") or the full original with headers (source "raw"). */
  text?: string;
  /** A .eml / .msg file as base64 (no "data:" prefix). */
  fileBase64?: string;
  fileName?: string;
  llm?: UserLlmConfig | null;
}

/** The most dangerous linked website, used (defanged) in community warnings. Never the sender's domain:
 *  a scam sent from gmail.com must not make anyone warn about gmail.com. */
function worstLinkDomain(links: EmailLink[]): string | null {
  const flagged = links
    .filter((l) => l.domain && l.verdict && l.verdict !== "SAFE")
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  return flagged[0]?.domain ?? null;
}

export function fromEmailScan(r: EmailScanVerdict, interception: InterceptionChannel): ScanVerdict {
  const e = r.email ?? ({} as Partial<EmailScanVerdict["email"]>);
  const links = Array.isArray(r.links) ? r.links : [];
  return {
    kind: "email",
    scanId: r.scan_id,
    target: r.target,
    scamDomain: worstLinkDomain(links),
    riskScore: r.risk_score,
    verdict: r.verdict,
    entityEn: r.impersonated_entity,
    entityAr: r.impersonated_entity_ar,
    officialDomains: r.official_domains ?? [],
    officialPhones: [],
    explanationEn: r.citizen_explanation_en,
    explanationAr: r.citizen_explanation_ar,
    redFlags: (r.red_flags ?? []).filter((f) => f.points > 0),
    harvested: [],
    ip: null,
    sslIssuer: null,
    domainAgeHours: null,
    cloaking: false,
    screenshot: null,
    syndicateEn: null,
    syndicateAr: null,
    engine: r.analyzer?.engine ?? "rules",
    interception,
    email: {
      source: r.source,
      subject: e.subject ?? "",
      date: e.date ?? null,
      hasHeaders: Boolean(e.has_headers),
      isBulk: Boolean(e.is_bulk),
      from: e.from ?? null,
      replyTo: e.reply_to ?? null,
      returnPath: e.return_path ?? null,
      bodyExcerpt: e.body_excerpt ?? "",
      auth: r.authentication ?? null,
      unicode: r.unicode?.findings ?? [],
      links,
      attachments: Array.isArray(r.attachments) ? r.attachments : [],
      campaigns: Array.isArray(r.campaigns) ? r.campaigns : [],
      userModel: r.user_model ?? null,
      llmRedFlags: Array.isArray(r.llm_red_flags) ? r.llm_red_flags : [],
      userLlmHost: r.analyzer?.user_llm_host ?? null,
      userLlmError: r.analyzer?.user_llm_error ?? null,
    },
  };
}

const REPORTER_KEY = "saqr-reporter-id";

/**
 * A random id for this browser, kept in localStorage. It links "This was a scam / fine" labels to the
 * personal email model without any name, phone number or account. Never derived from the user.
 */
export function getReporterId(): string {
  const fresh = () => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return "r-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  };
  try {
    const saved = window.localStorage.getItem(REPORTER_KEY);
    if (saved && /^[\w-]{16,64}$/.test(saved)) return saved;
    const id = fresh();
    window.localStorage.setItem(REPORTER_KEY, id);
    return id;
  } catch {
    return fresh(); // storage blocked (private mode): a one-off id still works for this scan
  }
}

export async function analyzeEmail(input: EmailScanInput, interception: InterceptionChannel): Promise<ScanVerdict> {
  const r = await request<EmailScanVerdict>("/api/analyze-email", {
    method: "POST",
    body: JSON.stringify({
      source: input.source,
      text: input.text ?? null,
      file_base64: input.fileBase64 ?? null,
      file_name: input.fileName ?? null,
      channel: "email",
      reporter_id: getReporterId(),
      interception_channel: interception,
      use_llm: true,
      follow_links: true,
      use_user_model: true,
      ...(input.llm ? { llm: input.llm } : {}),
    }),
  });
  return fromEmailScan(r, interception);
}

export interface CampaignReference {
  source_id: string;
  url: string;
  title: string;
}

export interface Campaign {
  id: string;
  title_en: string;
  title_ar: string;
  summary_en: string;
  summary_ar: string;
  brands: string[];
  terms: string[];
  min_terms: number;
  channels: string[];
  regions: string[];
  severity: string;
  first_seen: string;
  last_seen: string;
  references: CampaignReference[];
  indicators: { sender_domains: string[]; url_domains: string[] };
}

export interface CampaignFeed {
  format: "saqr-campaigns";
  version: number;
  generated_at: string;
  ttl_hours: number;
  sources: { id: string; name: string; url: string; license: string; ok: boolean; fetched_at: string; items: number }[];
  campaigns: Campaign[];
}

/** The scam-wave feed (GET /api/campaigns): used for the source links on a matched campaign. */
export async function getCampaigns(): Promise<CampaignFeed> {
  return request<CampaignFeed>("/api/campaigns");
}

export type EmailLabel = "scam" | "ham";

/** What POST /api/email-model/label answers (only `labels` is relied on, and only when present). */
export interface LabelResult {
  ok?: boolean;
  labels?: number;
  scam?: number;
  ham?: number;
  available?: boolean;
  user_model?: UserModelInfo;
}

/** Teach the personal email model: the server reuses the stored features of that scan (never the mail). */
export async function labelEmail(scanId: string, label: EmailLabel): Promise<LabelResult> {
  return request<LabelResult>("/api/email-model/label", {
    method: "POST",
    body: JSON.stringify({ reporter_id: getReporterId(), scan_id: scanId, label }),
  });
}

/** Download link for this browser's personal email model (JSON, format "saqr-user-model"). */
export function emailModelDownloadUrl(): string {
  return apiUrl(`/api/email-model/${encodeURIComponent(getReporterId())}`);
}
