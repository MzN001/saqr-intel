"use client";

import { CircleAlert, MapPin, ShieldCheck } from "lucide-react";
import { useId, useRef, useState, type FormEvent, type InputHTMLAttributes, type Ref } from "react";
import { Disclosure } from "./Disclosure";
import { useLang, type DictKey } from "@/lib/i18n";
import type { MapsScanInput } from "@/lib/api";

type Problem = "mlNeedName" | "mlNeedContact" | null;

const FIELD =
  "w-full min-w-0 rounded-2xl bg-muted px-3.5 py-2.5 text-[15px] text-ink outline-hidden ring-1 transition-shadow placeholder:text-ink-soft/80 focus:ring-2";

/**
 * "Check a Maps listing": the citizen copies the name, website and phone from a Google Maps card.
 * Folded by default so the Search & Maps tab stays calm.
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

  const ring = (bad: boolean) => (bad ? "ring-crimson-600" : "ring-line focus:ring-emerald-600");
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
      <label htmlFor={`${id}-${key}`} className="text-xs font-semibold text-ink-soft">
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
        className={`${FIELD} ${ring(bad)}`}
        {...extra}
      />
    </div>
  );

  return (
    <Disclosure summary={t("mlTitle")} icon={<MapPin className="size-4" aria-hidden />} className="max-w-xl">
      <form onSubmit={submit} noValidate className="grid gap-3">
        <p className="text-sm leading-relaxed text-ink-soft">{t("mlHint")}</p>
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
          <p id={errId} role="alert" className="flex items-center gap-1.5 text-sm font-medium text-crimson-700 dark:text-red-300">
            <CircleAlert className="size-4 shrink-0" aria-hidden /> {t(problem)}
          </p>
        )}
        <div>
          <button
            type="submit"
            className="inline-flex items-center justify-center gap-2 rounded-2xl bg-emerald-700 px-4 py-2.5 text-sm font-bold text-white shadow-sm transition hover:bg-emerald-800 active:scale-[0.97]"
          >
            <ShieldCheck className="size-4" aria-hidden />
            {t("mlButton")}
          </button>
        </div>
      </form>
    </Disclosure>
  );
}
