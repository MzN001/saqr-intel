"use client";

import { Check, Copy, Info, QrCode } from "lucide-react";
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
        data-testid="share-qr"
        className="inline-flex min-h-11 shrink-0 items-center gap-1.5 rounded-full border border-line bg-surface px-3.5 text-[13px] font-semibold text-ink transition-colors hover:bg-muted"
      >
        <QrCode className="size-4" aria-hidden />
        {t("shareQr")}
      </button>

      <Modal open={url !== null} onClose={() => setUrl(null)} title={t("shareQrTitle")}>
        {url && (
          <div className="space-y-4">
            <p className="text-[15px] text-ink-soft">{t("shareQrHint")}</p>
            <div className="mx-auto w-fit rounded-card border border-line bg-white p-4">
              <QRCodeSVG value={url} size={232} level="M" marginSize={1} fgColor="#111315" bgColor="#FFFFFF" title={url} />
            </div>
            <div className="flex items-center gap-2 rounded-control border border-line bg-muted p-1.5 ps-3">
              <code dir="ltr" className="min-w-0 flex-1 truncate text-[13px] text-ink">
                {url}
              </code>
              <button type="button" onClick={copy} className="btn-secondary min-h-10 px-3 text-[13px]">
                {copied ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
                {copied ? t("copied") : t("copyLink")}
              </button>
            </div>
            {isLocal && (
              <p className="flex gap-2 rounded-control bg-muted p-3 text-[13px] text-ink">
                <Info className="mt-0.5 size-4 shrink-0 text-ink-soft" aria-hidden />
                {t("shareQrLocal")}
              </p>
            )}
          </div>
        )}
      </Modal>
    </>
  );
}
