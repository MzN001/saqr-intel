"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useReducedMotion } from "framer-motion";
import { ChevronLeft, ChevronRight, Pause, Play, RotateCcw } from "lucide-react";
import { useLang } from "@/lib/i18n";
import { RiskMeter } from "../RiskMeter";
import {
  EDGES,
  KINDS,
  KIND_LABEL,
  LABEL_X,
  NODES,
  ROWS,
  STEPS,
  TEXT,
  VIEW_H,
  VIEW_W,
  type Bi,
  type NodeId,
  type PipelineNode,
  type StepKind,
  type TraceStep,
} from "./agentPipelineData";

const NODE_BY_ID = Object.fromEntries(NODES.map((n) => [n.id, n])) as Record<NodeId, PipelineNode>;
const LAST = STEPS.length - 1;
const BASE_MS = 1800;
const SPEEDS = [1, 1.5, 2] as const;

type KindStyle = { stroke: string; fill: string; dot: string };

/** Colour by meaning: emerald = read / verified, amber = police orchestration + approval, crimson = guardrail. */
function kindStyle(kind: StepKind): KindStyle {
  switch (kind) {
    case "goal":
      return { stroke: "stroke-ink", fill: "fill-ink", dot: "bg-ink" };
    case "coordination":
      return { stroke: "stroke-suspicious", fill: "fill-suspicious", dot: "bg-suspicious" };
    case "tool_read":
      return { stroke: "stroke-safe", fill: "fill-safe", dot: "bg-safe" };
    case "approval":
      return { stroke: "stroke-suspicious-ink", fill: "fill-suspicious-ink", dot: "bg-suspicious-ink" };
    case "command":
      return { stroke: "stroke-brand", fill: "fill-brand", dot: "bg-brand" };
    case "guardrail":
      return { stroke: "stroke-scam", fill: "fill-scam", dot: "bg-scam" };
    case "notification":
      return { stroke: "stroke-ink-soft", fill: "fill-ink-soft", dot: "bg-ink-soft" };
  }
}

/** Where a connector leaves / enters a node: bottom or top edge centre, depending on direction. */
function ports(a: PipelineNode, b: PipelineNode) {
  const down = b.y >= a.y ? 1 : -1;
  return { sx: a.x, sy: a.y + (down * a.h) / 2, ex: b.x, ey: b.y - (down * b.h) / 2, down };
}

/** Smooth vertical S-curve between two node centres. */
function edgePath(a: PipelineNode, b: PipelineNode): string {
  const { sx, sy, ex, ey } = ports(a, b);
  const my = (sy + ey) / 2;
  return `M ${sx} ${sy} C ${sx} ${my}, ${ex} ${my}, ${ex} ${ey}`;
}

const pairKey = (a: NodeId, b: NodeId) => (a < b ? `${a}|${b}` : `${b}|${a}`);

function NodeShape({ node, lang, active, ring }: { node: PipelineNode; lang: "en" | "ar"; active: boolean; ring: string }) {
  const { x, y, w, h, shape } = node;
  const left = x - w / 2;
  const top = y - h / 2;
  const rx = shape === "person" ? h / 2 : shape === "tool" ? 8 : 10;
  const dark = shape === "orchestrator";
  const lines = node.lines[lang];
  const hasSub = Boolean(node.sub);
  const lineH = shape === "tool" ? 16 : 18;
  const blockH = lines.length * lineH + (hasSub ? 16 : 0);
  const firstY = y - blockH / 2 + lineH * 0.72;
  const fontSize = shape === "orchestrator" ? 15 : shape === "tool" ? 13 : 14;

  let box = "fill-surface stroke-ink-soft";
  if (dark) box = "fill-ink stroke-ink";
  else if (shape === "tool") box = node.dashed ? "fill-muted stroke-ink-soft" : "fill-muted stroke-ink";

  return (
    <g
      className={`origin-center transition-all duration-300 ease-out [transform-box:fill-box] motion-reduce:transition-none ${
        active ? "scale-[1.04] opacity-100 drop-shadow-md" : ""
      }`}
    >
      {active && (
        <rect x={left - 6} y={top - 6} width={w + 12} height={h + 12} rx={rx + 6} className={`fill-none ${ring} opacity-40`} strokeWidth={5} />
      )}
      <rect
        x={left}
        y={top}
        width={w}
        height={h}
        rx={rx}
        className={box}
        strokeWidth={active ? 2 : 1.25}
        strokeDasharray={shape === "tool" && node.dashed ? "5 4" : undefined}
      />
      {lines.map((line, i) => (
        <text
          key={line}
          x={x}
          y={firstY + i * lineH}
          textAnchor="middle"
          fontSize={fontSize}
          fontWeight={dark ? 700 : 600}
          className={dark ? "fill-surface" : "fill-ink"}
        >
          {line}
        </text>
      ))}
      {node.sub && (
        <text
          x={x}
          y={firstY + lines.length * lineH + 1}
          textAnchor="middle"
          fontSize={11}
          letterSpacing={lang === "ar" ? 0 : 1.4}
          className={dark ? "fill-surface opacity-75" : "fill-ink-soft"}
        >
          {lang === "ar" ? node.sub.ar : node.sub.en.toUpperCase()}
        </text>
      )}
    </g>
  );
}

export default function AgentPipeline({ className = "", toolbar }: { className?: string; toolbar?: ReactNode }) {
  const { lang } = useLang();
  const L = (b: Bi) => b[lang];
  const reduced = useReducedMotion() ?? false;

  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<number>(1);

  const current: TraceStep = STEPS[step];
  const style = kindStyle(current.kind);
  const from = NODE_BY_ID[current.from];
  const to = NODE_BY_ID[current.to];
  const activePath = edgePath(from, to);
  const arrow = ports(from, to);

  const traversed = useMemo(() => new Set(STEPS.slice(0, step).map((s) => pairKey(s.from, s.to))), [step]);

  const pathRef = useRef<SVGPathElement>(null);
  const dotRef = useRef<SVGCircleElement>(null);
  const logRef = useRef<HTMLDivElement>(null);

  // Auto-advance; stops on the last step.
  useEffect(() => {
    if (!playing) return;
    const id = window.setTimeout(() => {
      if (step >= LAST) setPlaying(false);
      else setStep((s) => Math.min(LAST, s + 1));
    }, BASE_MS / speed);
    return () => window.clearTimeout(id);
  }, [playing, step, speed]);

  // Travelling dot: rAF along the active path (re-runs per step).
  useEffect(() => {
    const path = pathRef.current;
    const dot = dotRef.current;
    if (reduced || !path || !dot) return;
    const total = path.getTotalLength();
    const duration = 1100 / speed;
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      const pt = path.getPointAtLength(total * eased);
      dot.setAttribute("cx", String(pt.x));
      dot.setAttribute("cy", String(pt.y));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [step, speed, reduced]);

  // Keep the current log row visible inside the log's own scroll area (never scrolls the page).
  useEffect(() => {
    const box = logRef.current;
    const row = box?.querySelector<HTMLElement>(`[data-step="${step}"]`);
    if (!box || !row) return;
    const top = row.offsetTop - box.clientHeight / 2 + row.offsetHeight / 2;
    box.scrollTo({ top: Math.max(0, top), behavior: reduced ? "auto" : "smooth" });
  }, [step, reduced]);

  const seek = (i: number) => setStep(Math.max(0, Math.min(LAST, i)));
  const restart = () => {
    setStep(0);
    setPlaying(true);
  };
  const togglePlay = () => {
    if (!playing && step >= LAST) setStep(0);
    setPlaying((p) => !p);
  };

  const nodeName = (id: NodeId) => NODE_BY_ID[id].lines[lang].join(" ");
  const dim = "transition-opacity duration-300 motion-reduce:transition-none";

  return (
    <section className={`card min-w-0 overflow-hidden ${className}`}>
      <style>{`
        @keyframes ap-dash { to { stroke-dashoffset: -24; } }
        @media (prefers-reduced-motion: no-preference) { .ap-flow { animation: ap-dash 0.9s linear infinite; } }
      `}</style>

      {/* Header */}
      <header className="flex flex-wrap items-start justify-between gap-3 px-5 pt-5 pb-4">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold text-ink">{L(TEXT.title)}</h2>
          <p className="text-sm text-ink-soft">{L(TEXT.subtitle)}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <span className="chip chip-suspicious uppercase tracking-[0.08em] rtl:normal-case rtl:tracking-normal">{L(TEXT.badge)}</span>
          {toolbar}
        </div>
        <p className="w-full text-[13px] leading-relaxed text-ink-soft">{L(TEXT.caption)}</p>
      </header>

      {/* Diagram (always left-to-right) */}
      <div className="overflow-x-auto border-t border-line bg-canvas">
        <div dir="ltr" className="min-w-[960px] px-2 py-3">
          <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} role="img" aria-label={L(TEXT.diagramAlt)} className="block h-auto w-full">
            {ROWS.map((r) => (
              <text
                key={r.label.en}
                x={LABEL_X}
                y={r.y + 4}
                fontSize={12}
                fontWeight={600}
                letterSpacing={lang === "ar" ? 0 : 1.6}
                className="fill-ink-soft"
              >
                {lang === "ar" ? r.label.ar : r.label.en.toUpperCase()}
              </text>
            ))}

            <g className={`opacity-35 ${dim}`}>
              {EDGES.map(([a, b]) => {
                const seen = traversed.has(pairKey(a, b));
                return (
                  <path
                    key={pairKey(a, b)}
                    d={edgePath(NODE_BY_ID[a], NODE_BY_ID[b])}
                    className={`fill-none ${seen ? "stroke-ink-soft" : "stroke-line"} transition-colors duration-300`}
                    strokeWidth={seen ? 2 : 1.5}
                  />
                );
              })}
            </g>

            {/* Active edge: dash flow + arrow + travelling dot */}
            <g key={step}>
              <path d={activePath} className={`fill-none ${style.stroke} opacity-25`} strokeWidth={6} />
              <path
                ref={pathRef}
                d={activePath}
                className={`fill-none ${style.stroke} ${reduced ? "" : "ap-flow"}`}
                strokeWidth={2.5}
                strokeDasharray={reduced ? undefined : "8 4"}
                strokeLinecap="round"
              />
              <polygon
                points={`${arrow.ex - 7},${arrow.ey - arrow.down * 12} ${arrow.ex + 7},${arrow.ey - arrow.down * 12} ${arrow.ex},${arrow.ey - arrow.down * 1}`}
                className={style.fill}
              />
              {!reduced && <circle ref={dotRef} cx={arrow.sx} cy={arrow.sy} r={6} className={`${style.fill} stroke-surface`} strokeWidth={2} />}
            </g>

            {NODES.map((n) => {
              const active = n.id === current.from || n.id === current.to;
              return (
                <g key={n.id} className={`${active ? "opacity-100" : "opacity-35"} ${dim}`}>
                  <NodeShape node={n} lang={lang} active={active} ring={style.stroke} />
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      {/* Status line */}
      <div aria-live="polite" className="flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-line px-5 py-3 text-sm">
        <span className="chip">
          <span aria-hidden className={`size-2 rounded-full ${style.dot}`} />
          {L(KIND_LABEL[current.kind])}
        </span>
        <span className="text-ink-soft">
          {nodeName(current.from)} <span aria-hidden>{lang === "ar" ? "←" : "→"}</span> {nodeName(current.to)}
        </span>
        <span className="font-semibold text-ink">{L(current.summary)}</span>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2 border-t border-line px-5 py-3">
        <button type="button" onClick={restart} className="btn-secondary min-h-11 px-3">
          <RotateCcw className="size-4" aria-hidden />
          {L(TEXT.restart)}
        </button>
        <button type="button" onClick={() => seek(step - 1)} disabled={step === 0} className="btn-secondary min-h-11 px-3">
          <ChevronLeft className="size-4 rtl:rotate-180" aria-hidden />
          {L(TEXT.back)}
        </button>
        <button type="button" onClick={togglePlay} className="btn-primary min-h-11 min-w-24 px-4">
          {playing ? <Pause className="size-4" aria-hidden /> : <Play className="size-4" aria-hidden />}
          {playing ? L(TEXT.pause) : L(TEXT.play)}
        </button>
        <button type="button" onClick={() => seek(step + 1)} disabled={step === LAST} className="btn-secondary min-h-11 px-3">
          {L(TEXT.next)}
          <ChevronRight className="size-4 rtl:rotate-180" aria-hidden />
        </button>
        <label className="flex min-h-11 min-w-[12rem] flex-1 items-center gap-3">
          <span className="sr-only">{L(TEXT.seek)}</span>
          <input
            type="range"
            min={1}
            max={STEPS.length}
            value={step + 1}
            onChange={(e) => seek(Number(e.target.value) - 1)}
            className="w-full accent-ink"
          />
        </label>
        <span className="tabular-nums text-sm text-ink-soft">
          {step + 1} {L(TEXT.of)} {STEPS.length}
        </span>
        <label className="flex items-center">
          <span className="sr-only">{L(TEXT.speed)}</span>
          <select
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
            className="min-h-11 rounded-lg border border-line bg-surface px-2 text-sm text-ink tabular-nums"
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* Inspector + log */}
      <div className="grid gap-4 border-t border-line p-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Inspector step={current} lang={lang} />

        <div className="min-w-0">
          <h3 className="label-caps mb-2">{L(TEXT.log)}</h3>
          <div ref={logRef} className="relative max-h-80 overflow-y-auto rounded-lg border border-line">
            <ol>
              {STEPS.map((s, i) => {
                const on = i === step;
                return (
                  <li key={s.id}>
                    <button
                      type="button"
                      data-step={i}
                      onClick={() => seek(i)}
                      aria-current={on ? "step" : undefined}
                      className={`flex min-h-11 w-full items-start gap-2 border-b border-line px-3 py-2 text-start text-[13px] last:border-b-0 ${
                        on ? "bg-muted" : "hover:bg-muted/60"
                      } ${i > step ? "text-ink-soft" : "text-ink"}`}
                    >
                      <span className="w-5 shrink-0 tabular-nums text-ink-soft">{s.id}</span>
                      <span className="w-10 shrink-0 tabular-nums text-ink-soft" dir="ltr">
                        {s.t}
                      </span>
                      <span aria-hidden className={`mt-1.5 size-2 shrink-0 rounded-full ${kindStyle(s.kind).dot}`} />
                      <span className="min-w-0">
                        <span className="block text-[12px] text-ink-soft">
                          {nodeName(s.from)} {lang === "ar" ? "←" : "→"} {nodeName(s.to)}
                        </span>
                        <span className={on ? "font-semibold" : ""}>{L(s.summary)}</span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      </div>

      {/* Legend */}
      <ul className="flex flex-wrap gap-x-5 gap-y-2 border-t border-line px-5 py-3 text-[13px] text-ink-soft">
        {KINDS.map((k) => (
          <li key={k} className="flex items-center gap-2">
            <span aria-hidden className={`h-[3px] w-4 rounded-full ${kindStyle(k).dot}`} />
            {L(KIND_LABEL[k])}
          </li>
        ))}
      </ul>
    </section>
  );
}

function Inspector({ step, lang }: { step: TraceStep; lang: "en" | "ar" }) {
  const L = (b: Bi) => b[lang];
  return (
    <div className="min-w-0 space-y-3">
      <div>
        <p className="label-caps tabular-nums">
          {step.id} · <span dir="ltr">{step.t}</span>
        </p>
        <h3 className="mt-1 text-base font-semibold text-ink">{L(step.title)}</h3>
        <p className="text-sm text-ink-soft">{L(step.summary)}</p>
      </div>

      {step.visual === "cloaking" && (
        <div className="grid grid-cols-2 gap-3" dir="ltr">
          <figure className="rounded-lg border border-line bg-surface p-2">
            <figcaption className="label-caps mb-2">{L(TEXT.botView)}</figcaption>
            <div className="space-y-1.5 rounded bg-muted p-3">
              <div className="h-2 w-2/3 rounded bg-line" />
              <p className="text-[12px] text-ink-soft">{L(TEXT.parked)}</p>
              <div className="h-2 w-1/2 rounded bg-line" />
            </div>
          </figure>
          <figure className="rounded-lg border border-scam-ink/40 bg-surface p-2">
            <figcaption className="label-caps mb-2">{L(TEXT.phoneView)}</figcaption>
            <div className="space-y-1.5 rounded bg-muted p-3">
              <p className="text-[12px] font-semibold text-ink">{L(TEXT.fineTitle)}</p>
              <div className="rounded border border-line bg-surface px-2 py-1 text-[11px] text-ink-soft">{L(TEXT.card)}</div>
              <div className="rounded border border-line bg-surface px-2 py-1 text-[11px] text-ink-soft">{L(TEXT.otp)}</div>
              <div className="h-5 rounded bg-ink" />
            </div>
          </figure>
        </div>
      )}

      {step.visual === "verdict" && (
        <div className="space-y-3 rounded-lg border border-line p-3">
          <p className="tabular-nums text-3xl font-bold text-scam-ink" dir="ltr">
            96 <span className="text-lg text-ink-soft">/ 100</span>
          </p>
          <RiskMeter score={96} tone="scam" />
          <span className="chip chip-scam">{L(TEXT.verdictChip)}</span>
          <p className="text-sm text-ink" dir="ltr" lang="en">
            {TEXT.verdictEn}
          </p>
          <p className="text-sm text-ink" dir="rtl" lang="ar">
            {TEXT.verdictAr}
          </p>
        </div>
      )}

      {step.visual === "outcome" && (
        <div className="rounded-lg border border-line p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <h4 className="text-sm font-semibold text-ink">{L(TEXT.outcome)}</h4>
            <span className="chip">{L(TEXT.simulated)}</span>
          </div>
          <dl className="space-y-1.5 text-[13px]">
            {TEXT.outcomeRows.map((r) => (
              <div key={r.k.en} className="flex gap-2">
                <dt className="w-16 shrink-0 font-semibold text-ink">{L(r.k)}</dt>
                <dd className="min-w-0 break-words text-ink-soft">{L(r.v)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      <div>
        <h4 className="label-caps mb-1">{L(TEXT.payload)}</h4>
        <pre
          dir="ltr"
          className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-muted p-3 font-mono text-[12px] leading-relaxed text-ink"
        >
          {JSON.stringify(step.payload, null, 2)}
        </pre>
      </div>
    </div>
  );
}
