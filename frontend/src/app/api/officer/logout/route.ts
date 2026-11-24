import { cookies } from "next/headers";
import { SESSION_COOKIE, sameOrigin } from "@/lib/officer-session";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  if (!sameOrigin(request)) return Response.json({ ok: false, detail: "Cross-site request refused" }, { status: 403 });
  (await cookies()).delete(SESSION_COOKIE);
  return Response.json({ ok: true });
}
