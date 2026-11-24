import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE, sessionOk } from "@/lib/officer-session";

/** First gate for /police (the page re-checks on the server). */
export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (pathname === "/police/login" || pathname.startsWith("/police/login/")) return NextResponse.next();
  if (sessionOk(request.cookies.get(SESSION_COOKIE)?.value)) return NextResponse.next();
  const url = request.nextUrl.clone();
  url.pathname = "/police/login";
  url.search = `?next=${encodeURIComponent(pathname + search)}`;
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ["/police", "/police/:path*"],
};
