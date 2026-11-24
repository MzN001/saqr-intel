import type { NextRequest } from "next/server";
import { SESSION_COOKIE, backendBase, sameOrigin, sessionOk } from "@/lib/officer-session";

/**
 * Same-origin officer proxy: /api/officer/<path> -> <backend>/api/<path>, adding X-API-Key on the
 * server so the police key never reaches the browser. Only allow-listed method + path pairs pass.
 */

export const dynamic = "force-dynamic";
export const maxDuration = 60;

const ALLOW: { method: "GET" | "POST"; re: RegExp }[] = [
  { method: "GET", re: /^police\/state$/ },
  { method: "POST", re: /^police\/sync-telecom$/ },
  { method: "POST", re: /^police\/broadcast-warning$/ },
  { method: "GET", re: /^police\/takedown\/[^/]+$/ },
  { method: "GET", re: /^police\/detections\/\d+\/dossier$/ },
  { method: "GET", re: /^scans(\/[^/]+(\/screenshot)?)?$/ },
  { method: "GET", re: /^dossiers\/[^/]+(\/evidence-pack)?$/ },
  { method: "POST", re: /^generate-takedown\/[^/]+$/ },
  { method: "GET", re: /^awareness-alert$/ },
  { method: "GET", re: /^hunter\/(status|detections)$/ },
  { method: "POST", re: /^hunter\/sweep$/ },
  { method: "GET", re: /^syndicate-graph$/ },
  { method: "GET", re: /^syndicates(\/[^/]+)?$/ },
  { method: "GET", re: /^ct-stream$/ },
  { method: "GET", re: /^feedback\/false-alarms$/ },
  { method: "POST", re: /^feedback\/false-alarms\/[^/]+$/ },
];

const PASS_RESPONSE_HEADERS = ["content-type", "content-disposition", "content-length", "cache-control", "etag", "last-modified"];

type Ctx = { params: Promise<{ path: string[] }> };

async function handle(request: NextRequest, ctx: Ctx, method: "GET" | "POST"): Promise<Response> {
  if (!sessionOk(request.cookies.get(SESSION_COOKIE)?.value)) {
    return Response.json({ detail: "Officer sign-in required" }, { status: 401 });
  }
  if (method !== "GET" && !sameOrigin(request)) {
    return Response.json({ detail: "Cross-site request refused" }, { status: 403 });
  }

  const { path } = await ctx.params;
  const segments = path ?? [];
  if (segments.some((s) => !s || s === "." || s === ".." || s.includes("/") || s.includes("\\"))) {
    return Response.json({ detail: "Not found" }, { status: 404 });
  }
  const joined = segments.join("/");
  if (!ALLOW.some((a) => a.method === method && a.re.test(joined))) {
    return Response.json({ detail: "Not allowed through the officer proxy" }, { status: 404 });
  }

  const target = `${backendBase()}/api/${segments.map(encodeURIComponent).join("/")}${request.nextUrl.search}`;
  const headers = new Headers({ accept: request.headers.get("accept") ?? "*/*" });
  const key = (process.env.POLICE_API_KEY ?? "").replace(/[﻿\s]+/g, "");
  if (key) headers.set("X-API-Key", key);
  const contentType = request.headers.get("content-type");
  if (contentType) headers.set("content-type", contentType);
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) headers.set("x-forwarded-for", forwardedFor);

  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method,
      headers,
      body: method === "GET" ? undefined : await request.arrayBuffer(),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(55_000),
    });
  } catch {
    return Response.json({ detail: "The SAQR backend is not reachable (it may be waking up). Try again shortly." }, { status: 502 });
  }

  if (upstream.status === 401) {
    void upstream.body?.cancel().catch(() => undefined);
    return Response.json(
      { detail: "The backend refused the police API key: POLICE_API_KEY on the web server does not match the backend's key." },
      { status: 502 },
    );
  }

  const out = new Headers({ "cache-control": "no-store" });
  for (const h of PASS_RESPONSE_HEADERS) {
    const v = upstream.headers.get(h);
    if (v) out.set(h, v);
  }
  // fetch() already decoded any gzip body, so a forwarded content-length could be wrong.
  if (upstream.headers.get("content-encoding")) out.delete("content-length");
  return new Response(upstream.body, { status: upstream.status, headers: out });
}

export function GET(request: NextRequest, ctx: Ctx) {
  return handle(request, ctx, "GET");
}

export function POST(request: NextRequest, ctx: Ctx) {
  return handle(request, ctx, "POST");
}
