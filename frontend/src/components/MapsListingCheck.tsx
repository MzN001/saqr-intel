"use client";

import { Info } from "lucide-react";
import { useId, useRef, useState, type FormEvent, type InputHTMLAttributes, type Ref } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import type { MapsScanInput } from "@/lib/api";

type Problem = "mlNeedName" | "mlNeedContact" | null;


/**
 * "Check a Maps listing": the citizen copies the name, website and phone from a Google Maps card.
 * Shown as its own card in the Search & Maps window.
 */
export function MapsListingCheck({ onCheck }: { onCheck: (input: MapsScanInput) => void }) {
  const { t } = useLang();
  const id = useId();
  const [name, setName] = useState("");
  const [website, setWebsite] = useState("");
  const [phone, setPhone] = useState("");
  const [problem, setProblem] = useState<Problem>(null);
  const nameRef = useRef<HTMLInputElement>(null);
  const siteRef = useRef<HTMLInputElement>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const n = name.trim();
    const w = website.trim();
    const p = phone.trim();
    if (!n) {
      setProblem("mlNeedName");
      nameRef.current?.focus();
      return;
    }
    if (!w && !p) {
      setProblem("mlNeedContact");
      siteRef.current?.focus();
      return;
    }
    setProblem(null);
    onCheck({ business_name: n, ...(w ? { website: w } : {}), ...(p ? { phone: p } : {}) });
  };


  const errId = `${id}-error`;
  const field = (
    key: string,
    label: DictKey,
    placeholder: DictKey,
    value: string,
    set: (v: string) => void,
    bad: boolean,
    extra: InputHTMLAttributes<HTMLInputElement> & { ref?: Ref<HTMLInputElement> },
  ) => (
    <div className="grid gap-1.5">
      <label htmlFor={`${id}-${key}`} className="text-[13px] font-semibold text-ink">
        {t(label)}
      </label>
      <input
        id={`${id}-${key}`}
        type="text"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(e) => {
          set(e.target.value);
          if (problem) setProblem(null);
        }}
        placeholder={t(placeholder)}
        aria-invalid={bad || undefined}
        aria-describedby={bad ? errId : undefined}
        className={`field ${bad ? "border-ink" : ""}`}
        {...extra}
      />
    </div>
  );

  return (
    <section aria-labelledby={`${id}-title`} className="card p-5 sm:p-6" data-testid="maps-listing-check">
      <h2 id={`${id}-title`} className="text-[20px] font-semibold leading-tight text-ink">
        {t("mlTitle")}
      </h2>
      <form onSubmit={submit} noValidate className="mt-2 grid gap-3">
        <p className="text-[15px] leading-relaxed text-ink-soft">{t("mlHint")}</p>
        {field("name", "mlName", "mlNamePh", name, setName, problem === "mlNeedName", {
          ref: nameRef,
          enterKeyHint: "next",
          maxLength: 200,
        })}
        <div className="grid gap-3 sm:grid-cols-2">
          {field("website", "mlWebsite", "mlWebsitePh", website, setWebsite, problem === "mlNeedContact", {
            ref: siteRef,
            inputMode: "url",
            autoCapitalize: "off",
            autoCorrect: "off",
            dir: "ltr",
            maxLength: 512,
          })}
          {field("phone", "mlPhone", "mlPhonePh", phone, setPhone, problem === "mlNeedContact", {
            type: "tel",
            inputMode: "tel",
            dir: "ltr",
            maxLength: 32,
          })}
        </div>
        {problem && (
          <p id={errId} role="alert" className="flex items-center gap-1.5 text-[14px] font-medium text-ink">
            <Info className="size-4 shrink-0" aria-hidden /> {t(problem)}
          </p>
        )}
        <div>
          <button type="submit" className="btn-primary w-full sm:w-auto" data-testid="maps-listing-submit">
            {t("mlButton")}
          </button>
        </div>
      </form>
    </section>
  );
}
