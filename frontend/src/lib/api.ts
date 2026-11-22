export type InterceptionChannel =
  | "MOBILE_OS_SHARE_SHEET"
  | "AUTO_TELECOM_DNS"
  | "AUTO_SMS_GUARD"
  | "CITIZEN_MANUAL_CHECK"
  | "PC_BROWSER_EXTENSION"
  | "MANUAL";

export type VerdictLabel = "SAFE" | "SUSPICIOUS" | "HIGH-RISK SCAM";

export interface RedFlag {
  code: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  points: number;
  en: string;
  ar: string;
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
  kind: "url" | "maps";
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
    res = await fetch(path, {
      ...init,
      headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
      cache: "no-store",
    });
  } catch {
    throw new ApiError("SAQR-INTEL backend is unreachable. Is it running on port 8000?", 0);
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

export async function getAwareness(params: { entity?: string; useLlm?: boolean } = {}): Promise<AwarenessAlert> {
  const q = new URLSearchParams({ hours: "168" });
  if (params.entity) q.set("entity", params.entity);
  if (params.useLlm === false) q.set("use_llm", "false");
  return request<AwarenessAlert>(`/api/awareness-alert?${q.toString()}`);
}
