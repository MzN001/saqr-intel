"use client";

import { Check, Copy, QrCode, TriangleAlert } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { useState } from "react";
import { useLang } from "@/lib/i18n";
import { copyText } from "@/lib/share";
import { Modal } from "./Modal";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"]);

export function ShareQrButton() {
  const { t } = useLang();
  const [url, setUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const isLocal = url ? LOCAL_HOSTS.has(new URL(url).hostname) : false;

  const open = () => {
    setCopied(false);
    setUrl(`${window.location.origin}/citizen`);
  };

  const copy = async () => {
    if (url && (await copyText(url))) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={open}
        aria-label={t("shareQr")}
        title={t("shareQr")}
        className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full bg-muted px-2.5 text-xs font-semibold text-ink ring-1 ring-line transition hover:bg-line md:px-3"
      >
        <QrCode className="size-4" />
        <span className="hidden md:inline">{t("shareQr")}</span>
      </button>

      <Modal open={url !== null} onClose={() => setUrl(null)} title={t("shareQrTitle")}>
        {url && (
          <div className="space-y-4">
            <p className="text-sm text-ink-soft">{t("shareQrHint")}</p>
            <div className="mx-auto w-fit rounded-3xl bg-white p-4 shadow-sm ring-1 ring-line">
              <QRCodeSVG
                value={url}
                size={232}
                level="M"
                marginSize={1}
                fgColor="#0B192C"
                bgColor="#FFFFFF"
                title={url}
              />
            </div>
            <div className="flex items-center gap-2 rounded-2xl bg-muted p-2 ps-3 ring-1 ring-line">
              <code dir="ltr" className="min-w-0 flex-1 truncate text-sm text-ink">
                {url}
              </code>
              <button
                type="button"
                onClick={copy}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-surface px-3 py-2 text-xs font-bold text-ink ring-1 ring-line hover:bg-line"
              >
                {copied ? <Check className="size-4 text-emerald-600" /> : <Copy className="size-4" />}
                {copied ? t("copied") : t("copyLink")}
              </button>
            </div>
            {isLocal && (
              <p className="flex gap-2 rounded-2xl bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-400/25">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" />
                {t("shareQrLocal")}
              </p>
            )}
          </div>
        )}
      </Modal>
    </>
  );
}
