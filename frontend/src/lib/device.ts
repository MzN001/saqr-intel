/**
 * This phone's SAQR device tag, e.g. "saqr7f3k2a". It goes into the phone's DNS setting (so the
 * NextDNS log says which phone blocked a scam) and into its alert sign-up, so a block alert reaches
 * only the phone that tried to open the scam, never a friend's phone on the same shield.
 * Letters and digits only: NextDNS turns "-" in a device name into a separator.
 */
const KEY = "saqr-device";

export function getDeviceTag(): string | null {
  try {
    const saved = localStorage.getItem(KEY);
    if (saved && /^[a-z0-9]{6,24}$/.test(saved)) return saved;
    const bytes = crypto.getRandomValues(new Uint8Array(6));
    const tag = "saqr" + Array.from(bytes, (b) => "abcdefghijklmnopqrstuvwxyz0123456789"[b % 36]).join("");
    localStorage.setItem(KEY, tag);
    return tag;
  } catch {
    return null;
  }
}
