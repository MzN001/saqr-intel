"use client";

import { Check } from "lucide-react";
import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode, type RefObject } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import { useScamAlertsOn } from "./ScamAlertsCard";

/*
 * "Set up in three steps": progress + the guidance animation (DESIGN.md "Step guidance").
 *
 * Progress (localStorage `saqr-setup-progress`, shared by the desktop cards, the phone rows and the header):
 *   1 Check a link       done once a check has finished (this session or any earlier one)
 *   2 Phone shield       done once a phone-shield setup was opened (drawer or the Shield tab). A web page
 *                        cannot see the phone's DNS setting, so this never claims the shield is ON.
 *   3 Scam alerts        done when this browser really has a push subscription (useScamAlertsOn)
 * Current step = the first one not done (none when all three are done).
 *
 * Guidance: the first time the list scrolls into view, steps 1 -> 2 -> 3 each turn green for 900 ms
 * (one-time sweep), then the current step stays green with a slow breathing glow. Reduced motion: no
 * sweep, no breathing; the current step is simply green. Hover / keyboard focus also turns a step green.
 */

const KEY = "saqr-setup-progress";
type Stored = { checked: boolean; shield: boolean };
const EMPTY: Stored = { checked: false, shield: false };

let cache: Stored | null = null;
const listeners = new Set<() => void>();

function read(): Stored {
  if (cache) return cache;
  try {
    const raw = JSON.parse(window.localStorage.getItem(KEY) ?? "{}") as Partial<Stored>;
    cache = { checked: raw.checked === true, shield: raw.shield === true };
  } catch {
    cache = { ...EMPTY };
  }
  return cache;
}

export function markSetupStep(step: keyof Stored) {
  const cur = read();
  if (cur[step]) return;
  cache = { ...cur, [step]: true };
  try {
    window.localStorage.setItem(KEY, JSON.stringify(cache));
  } catch {
    /* storage unavailable (private mode): progress lasts for this page only */
  }
  listeners.forEach((cb) => cb());
}

const store = {
  subscribe(cb: () => void) {
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  },
  get: read,
  server: () => EMPTY,
};

export type SetupProgress = { done: [boolean, boolean, boolean]; current: 0 | 1 | 2 | null };

export function useSetupProgress(): SetupProgress {
  const stored = useSyncExternalStore(store.subscribe, store.get, store.server);
  const alerts = useScamAlertsOn();
  const done: [boolean, boolean, boolean] = [stored.checked, stored.shield, alerts];
  const idx = done.indexOf(false);
  return { done, current: idx === -1 ? null : (idx as 0 | 1 | 2) };
}

const REDUCE = "(prefers-reduced-motion: reduce)";
function subscribeReduce(cb: () => void) {
  const mq = window.matchMedia(REDUCE);
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
}

/** Per-step highlight: "lit" during the sweep, "current" afterwards (or straight away with reduced motion). */
function useStepGuide(list: RefObject<HTMLElement | null>, current: number | null): (i: number) => "lit" | "current" | undefined {
  const reduce = useSyncExternalStore(subscribeReduce, () => window.matchMedia(REDUCE).matches, () => false);
  const [sweep, setSweep] = useState<number | null>(null);
  const [swept, setSwept] = useState(false);

  useEffect(() => {
    const el = list.current;
    if (!el || reduce || swept) return;
    const timers: number[] = [];
    const io = new IntersectionObserver(
      (entries) => {
        if (!entries.some((e) => e.isIntersecting)) return;
        io.disconnect();
        [0, 1, 2].forEach((i) => timers.push(window.setTimeout(() => setSweep(i), i * 900)));
        timers.push(
          window.setTimeout(() => {
            setSweep(null);
            setSwept(true);
          }, 2700),
        );
      },
      { threshold: 0.45 },
    );
    io.observe(el);
    return () => {
      io.disconnect();
      timers.forEach((id) => window.clearTimeout(id));
    };
  }, [list, reduce, swept]);

  return (i) => {
    if (sweep !== null) return i === sweep ? "lit" : undefined;
    if ((swept || reduce) && current === i) return "current";
    return undefined;
  };
}

type StepDef = { title: DictKey; body: DictKey; doneBody?: DictKey; action: ReactNode };

/** Desktop: three white cards in a row. */
export function SetupCards({ steps }: { steps: [StepDef, StepDef, StepDef] }) {
  const { t } = useLang();
  const { done, current } = useSetupProgress();
  const list = useRef<HTMLOListElement>(null);
  const guide = useStepGuide(list, current);
  return (
    <ol ref={list} className="mt-5 grid gap-4 md:grid-cols-3">
      {steps.map((s, i) => (
        <li
          key={s.title}
          className="guide-step flex flex-col rounded-tile border border-line bg-surface p-5 shadow-card"
          data-testid={`step-${i + 1}`}
          data-done={done[i] || undefined}
          data-guide={guide(i)}
        >
          <div className="flex items-center gap-2">
            <span
              className={`guide-badge grid size-8 place-items-center rounded-full border-[1.5px] text-[14px] font-semibold tabular-nums ${
                done[i] ? "border-brand bg-brand text-on-brand" : "border-ink text-ink"
              }`}
              aria-hidden
            >
              {done[i] ? <Check className="size-4" strokeWidth={2.6} /> : i + 1}
            </span>
            {done[i] && <span className="text-[13px] font-semibold text-brand-ink">{t("stepDone")}</span>}
            <span className="sr-only">{done[i] ? `${i + 1}. ${t("stepDone")}` : `${i + 1}.`}</span>
          </div>
          <h3 className="mt-3 text-[17px] font-semibold leading-snug text-ink">{t(s.title)}</h3>
          <p className="mt-1 text-[15px] leading-relaxed text-ink-soft">{t(s.body)}</p>
          <div className="mt-auto flex flex-wrap gap-2 pt-4">{s.action}</div>
        </li>
      ))}
    </ol>
  );
}

/** Phone: a vertical list of white rows, the action on the trailing edge. */
export function SetupRows({ steps }: { steps: [StepDef, StepDef, StepDef] }) {
  const { t } = useLang();
  const { done, current } = useSetupProgress();
  const list = useRef<HTMLOListElement>(null);
  const guide = useStepGuide(list, current);
  return (
    <ol ref={list} className="mt-3 flex flex-col gap-[9px]">
      {steps.map((s, i) => (
        <li
          key={s.title}
          className="guide-step flex items-start gap-3 rounded-row border border-line bg-surface py-3 ps-[13px] pe-2"
          data-testid={`step-${i + 1}`}
          data-done={done[i] || undefined}
          data-guide={guide(i)}
        >
          <span
            className={`guide-badge mt-0.5 grid size-6 shrink-0 place-items-center rounded-[8px] border text-[13px] font-bold tabular-nums ${
              done[i] ? "border-brand bg-brand text-on-brand" : "border-line text-ink-soft"
            }`}
            aria-hidden
          >
            {done[i] ? <Check className="size-3.5" strokeWidth={2.8} /> : i + 1}
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="text-[15px] font-semibold leading-snug text-ink">
              {t(s.title)}
              <span className="sr-only"> · {done[i] ? t("stepDone") : `${i + 1}/3`}</span>
            </h3>
            <p className="mt-0.5 text-[13px] leading-[1.45] text-ink-soft">{t(done[i] && s.doneBody ? s.doneBody : s.body)}</p>
          </div>
          {s.action && <div className="shrink-0 self-center">{s.action}</div>}
        </li>
      ))}
    </ol>
  );
}
