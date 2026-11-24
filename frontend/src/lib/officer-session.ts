import "server-only";

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * Officer session for /police: one shared passcode -> a signed, httpOnly cookie.
 * Server-only env vars (never NEXT_PUBLIC_): POLICE_PASSCODE, POLICE_API_KEY.
 */

export type AuthMode = "locked" | "dev-open" | "unconfigured";

export const SESSION_COOKIE = "saqr_officer";
export const SESSION_MAX_AGE = 12 * 60 * 60; // seconds

const clean = (v: string | undefined) => (v ?? "").replace(/[﻿\s]+/g, "");

export function authMode(): AuthMode {
  if (clean(process.env.POLICE_PASSCODE)) return "locked";
  return process.env.NODE_ENV === "production" ? "unconfigured" : "dev-open";
}

function signingKey(): Buffer | null {
  const secret = clean(process.env.POLICE_API_KEY) || clean(process.env.POLICE_PASSCODE);
  if (!secret) return null;
  return createHmac("sha256", secret).update("saqr-officer-session-v1").digest();
}

function mac(payload: string, key: Buffer): string {
  return createHmac("sha256", key).update(payload).digest("base64url");
}

/** Token = "<exp unix seconds>.<HMAC-SHA256>". */
export function sign(exp: number): string {
  const key = signingKey();
  if (!key) throw new Error("Officer session key is not configured");
  const payload = String(Math.floor(exp));
  return `${payload}.${mac(payload, key)}`;
}

export function verify(token: string | undefined | null): boolean {
  if (!token) return false;
  const key = signingKey();
  if (!key) return false;
  const dot = token.indexOf(".");
  if (dot <= 0) return false;
  const payload = token.slice(0, dot);
  if (!/^\d{1,12}$/.test(payload)) return false;
  const given = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(mac(payload, key));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return false;
  return Number(payload) > Math.floor(Date.now() / 1000);
}

/** Compares SHA-256 digests so the comparison is constant-time and length-independent. */
export function passcodeOk(input: unknown): boolean {
  const expected = clean(process.env.POLICE_PASSCODE);
  if (!expected || typeof input !== "string" || !input) return false;
  const a = createHash("sha256").update(input.trim()).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/** True when the request may use the officer API / page. */
export function sessionOk(token: string | undefined | null): boolean {
  const mode = authMode();
  if (mode === "dev-open") return true;
  if (mode === "unconfigured") return false;
  return verify(token);
}

export function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/",
    maxAge: SESSION_MAX_AGE,
  };
}

/** Same-site guard for state-changing requests: the Origin host must match the request host. */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  let originHost: string;
  try {
    originHost = new URL(origin).host;
  } catch {
    return false;
  }
  const host = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim() || request.headers.get("host") || new URL(request.url).host;
  return originHost.toLowerCase() === host.toLowerCase();
}

/** Backend base URL, cleaned the same way as next.config.mjs. */
export function backendBase(): string {
  const c = (v: string | undefined) => (v ?? "").replace(/[﻿\s]+/g, "").replace(/\/+$/, "");
  return c(process.env.NEXT_PUBLIC_API_URL) || c(process.env.SAQR_BACKEND_URL) || "http://127.0.0.1:8000";
}

/** Only same-site /police paths are allowed as a post-login destination. */
export function safeNext(next: string | null | undefined): string {
  if (!next || typeof next !== "string") return "/police";
  if (!/^\/police(?:[/?#]|$)/.test(next) || next.includes("\\")) return "/police";
  if (next.startsWith("/police/login")) return "/police";
  return next;
}
