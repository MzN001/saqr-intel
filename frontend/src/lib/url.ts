const URL_RE = /https?:\/\/[^\s<>"']+/i;
const BARE_DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/[^\s<>"']*)?/i;

export function extractUrl(input: string | null | undefined): string | null {
  if (!input) return null;
  const text = input.trim();
  const full = text.match(URL_RE);
  if (full) return full[0].replace(/[.,;:!?)\]]+$/, "");
  const bare = text.match(BARE_DOMAIN_RE);
  return bare ? bare[0].replace(/[.,;:!?)\]]+$/, "") : null;
}

export function isMapsUrl(url: string): boolean {
  const u = url.toLowerCase();
  return u.includes("maps.google") || u.includes("google.com/maps") || u.includes("maps.app.goo.gl");
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
