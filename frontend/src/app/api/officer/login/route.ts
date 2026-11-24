import { cookies } from "next/headers";
import { SESSION_COOKIE, SESSION_MAX_AGE, authMode, cookieOptions, passcodeOk, sameOrigin, sign } from "@/lib/officer-session";

export const dynamic = "force-dynamic";

const WINDOW_MS = 10 * 60 * 1000;
const MAX_TRIES = 5;
// In-memory per-IP throttle (one serverless instance / one node process; good enough for a shared passcode).
const tries = new Map<string, number[]>();

function clientIp(request: Request): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip")?.trim() ||
    "local"
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function POST(request: Request) {
  if (!sameOrigin(request)) return Response.json({ ok: false, detail: "Cross-site request refused" }, { status: 403 });
  if (authMode() !== "locked") return Response.json({ ok: false, detail: "Police access is not configured" }, { status: 503 });

  const ip = clientIp(request);
  const now = Date.now();
  const recent = (tries.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (recent.length >= MAX_TRIES) {
    tries.set(ip, recent);
    return Response.json({ ok: false, detail: "Too many attempts" }, { status: 429 });
  }

  let passcode: unknown = null;
  try {
    const body = (await request.json()) as { passcode?: unknown };
    passcode = body?.passcode;
  } catch {
    /* treated as a wrong passcode */
  }

  if (!passcodeOk(passcode)) {
    recent.push(now);
    tries.set(ip, recent);
    if (tries.size > 5000) {
      for (const [k, v] of tries) if (v.every((t) => now - t >= WINDOW_MS)) tries.delete(k);
    }
    await sleep(600);
    return Response.json({ ok: false, detail: "Wrong passcode" }, { status: 401 });
  }

  tries.delete(ip);
  const cookieStore = await cookies();
  cookieStore.set(SESSION_COOKIE, sign(Math.floor(now / 1000) + SESSION_MAX_AGE), cookieOptions());
  return Response.json({ ok: true });
}
