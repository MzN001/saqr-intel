"use client";

import { BatteryFull, Signal, Wifi } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

/*
 * The device frame for the Search & Maps and SMS demos. The page header, notice strip and footer moved to
 * CitizenChrome.tsx. Inside the frame the screen is device-styled (bg-screen + explicit dark greys), and the
 * bezel stays a dark device colour in both themes.
 */

function useClock(): string {
  const [time, setTime] = useState("");
  useEffect(() => {
    const tick = () =>
      setTime(new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Dubai" }));
    tick();
    const id = window.setInterval(tick, 15_000);
    return () => window.clearInterval(id);
  }, []);
  return time;
}

/** Capped at 360px and centred on phones (no bezel there), a 390px device with a bezel from `sm`. */
export function PhoneFrame({ children, carrier = "e&" }: { children: ReactNode; carrier?: string }) {
  const time = useClock();
  return (
    <div className="relative mx-auto w-full max-w-[360px] sm:w-[390px] sm:max-w-none">
      <div className="relative overflow-hidden rounded-card border border-line bg-screen shadow-card dark:bg-[#202124] sm:rounded-[3.2rem] sm:border-[11px] sm:border-obsidian sm:shadow-overlay dark:sm:border-black">
        <div className="relative flex h-11 items-center justify-between bg-screen px-6 text-[13px] font-semibold text-obsidian dark:bg-[#202124] dark:text-gray-100" dir="ltr">
          <span className="tabular-nums">{time}</span>
          <span className="absolute left-1/2 top-2 hidden h-7 w-28 -translate-x-1/2 rounded-full bg-obsidian sm:block dark:bg-black" />
          <span className="flex items-center gap-1.5">
            <span className="text-[11px] font-bold">{carrier}</span>
            <Signal className="size-3.5" />
            <Wifi className="size-3.5" />
            <BatteryFull className="size-4" />
          </span>
        </div>
        <div className="relative h-[600px] overflow-y-auto no-scrollbar sm:h-[720px]">{children}</div>
        <div className="hidden h-6 items-center justify-center bg-screen sm:flex dark:bg-[#202124]">
          <span className="h-1 w-28 rounded-full bg-obsidian/80 dark:bg-white/70" />
        </div>
      </div>
    </div>
  );
}
