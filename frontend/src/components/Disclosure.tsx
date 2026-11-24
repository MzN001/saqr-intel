"use client";

import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";

/**
 * "Show more" fold for secondary detail (steps, fine print, advanced options).
 * Native <details>: keyboard, screen readers and find-in-page work with no script.
 */
export function Disclosure({
  summary,
  icon,
  children,
  className = "",
  defaultOpen = false,
}: {
  summary: ReactNode;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
  defaultOpen?: boolean;
}) {
  return (
    <details className={`group border-t border-line ${className}`} open={defaultOpen || undefined}>
      <summary className="flex min-h-12 cursor-pointer list-none items-center gap-2 py-2 text-[14px] font-semibold text-ink-soft transition-colors hover:text-ink [&::-webkit-details-marker]:hidden">
        {icon && <span className="shrink-0">{icon}</span>}
        <span className="min-w-0 flex-1">{summary}</span>
        <ChevronDown className="size-4 shrink-0 transition-transform duration-200 group-open:rotate-180" aria-hidden />
      </summary>
      <div className="pb-3">{children}</div>
    </details>
  );
}
