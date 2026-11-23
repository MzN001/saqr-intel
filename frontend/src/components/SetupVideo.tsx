"use client";

/**
 * Silent "setup video" for the phone DNS shield: an animated walkthrough of the real settings path,
 * drawn as phone screens. A highlight ring glides to the option to choose, a tap ripple presses it,
 * and the next screen arrives. Plays like a video (play / pause / replay / jump to a step), follows
 * the site language, and uses the hostname the citizen is about to paste. No audio.
 */
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  Bell,
  Bluetooth,
  Camera,
  Check,
  ChevronLeft,
  ChevronRight,
  Download,
  Globe,
  Lock,
  MessageCircle,
  Pause,
  Phone,
  Play,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  ShoppingBag,
  Smartphone,
  Volume2,
  Wifi,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Modal } from "./Modal";
import { useLang } from "@/lib/i18n";

type Lang = "en" | "ar";
interface Scene {
  /** Draws the phone screen; `p` is this scene's progress 0..1. Mark the target with data-hl. */
  render: (p: number) => ReactNode;
  caption: Record<Lang, string>;
  ms: number;
  /** Screen colour behind the status bar / notch. */
  bg?: string;
  /** false: no tap on this screen (typing, passcode, final screen). */
  tap?: boolean;
}

const EASE = [0.16, 1, 0.3, 1] as const;
const TAP_AT = 0.62; // fraction of a scene when the finger "taps" the highlighted option

/* ------------------------------------------------------------------ shared phone primitives */

function Row({ icon, label, sub, hl, value, tone = "plain", pressed }: {
  icon?: ReactNode; label: string; sub?: string; hl?: boolean; value?: string; tone?: "plain" | "android"; pressed?: boolean;
}) {
  return (
    <div
      data-hl={hl ? "" : undefined}
      className={`flex items-center gap-3 px-4 transition-colors duration-150 ${tone === "android" ? "py-3" : "py-2.5"} ${pressed ? "bg-black/10" : ""}`}
    >
      {icon && <span className="grid size-7 shrink-0 place-items-center rounded-lg text-white">{icon}</span>}
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[13px] font-medium text-[#111]">{label}</span>
        {sub && <span className="block truncate text-[11px] text-[#666]">{sub}</span>}
      </span>
      {value && <span className="max-w-[45%] truncate text-[11px] text-[#777]">{value}</span>}
      {tone === "plain" && <ChevronRight className="size-3.5 shrink-0 text-[#c4c4c6]" />}
    </div>
  );
}

const Icon = ({ bg, children }: { bg: string; children: ReactNode }) => (
  <span className="grid size-7 place-items-center rounded-lg" style={{ background: bg }}>{children}</span>
);

function IosNav({ title, back }: { title: string; back?: string }) {
  return (
    <div className="bg-[#f2f2f7] px-3 pb-2 pt-1">
      {back && (
        <span className="flex items-center text-[13px] text-[#0a84ff]">
          <ChevronLeft className="size-4" />
          {back}
        </span>
      )}
      <p className={`${back ? "mt-1 text-[22px]" : "mt-3 text-[26px]"} font-bold tracking-tight text-black`}>{title}</p>
    </div>
  );
}

function AndroidNav({ title }: { title: string }) {
  return (
    <div className="flex items-center gap-3 px-4 pb-3 pt-5">
      <ChevronLeft className="size-5 text-[#333]" />
      <p className="text-[19px] font-semibold text-[#111]">{title}</p>
    </div>
  );
}

const Group = ({ children }: { children: ReactNode }) => (
  <div className="mx-3 overflow-hidden rounded-xl bg-white [&>*+*]:border-t [&>*+*]:border-[#e5e5ea]">{children}</div>
);

const AGroup = ({ children }: { children: ReactNode }) => (
  <div className="mx-3 overflow-hidden rounded-2xl bg-white">{children}</div>
);

/* ------------------------------------------------------------------ Android scenes */

function androidScenes(host: string): Scene[] {
  const pressed = (p: number) => p > TAP_AT && p < TAP_AT + 0.18;
  return [
    {
      ms: 3200,
      bg: "#1e3a5f",
      caption: { en: "Open the Settings app.", ar: "افتح تطبيق الإعدادات." },
      render: (p) => (
        <div className="flex h-full flex-col bg-gradient-to-b from-[#1e3a5f] to-[#0b192c] px-4 pt-10">
          <div className="mx-auto mb-8 flex w-full items-center gap-2 rounded-full bg-white/90 px-3 py-2 text-[12px] text-[#555]">
            <Search className="size-3.5" /> Search
          </div>
          <div className="grid grid-cols-4 gap-x-2 gap-y-5">
            {[
              ["Phone", <Phone key="i" className="size-5" />, "#22c55e"],
              ["Messages", <MessageCircle key="i" className="size-5" />, "#3b82f6"],
              ["Browser", <Globe key="i" className="size-5" />, "#f59e0b"],
              ["Camera", <Camera key="i" className="size-5" />, "#64748b"],
              ["Store", <ShoppingBag key="i" className="size-5" />, "#10b981"],
              ["Settings", <Settings key="i" className="size-5" />, "#6b7280"],
            ].map(([label, icon, bg]) => (
              <div key={label as string} className="flex flex-col items-center gap-1">
                <span
                  data-hl={label === "Settings" ? "" : undefined}
                  className={`grid size-12 place-items-center rounded-2xl text-white shadow transition-transform duration-150 ${label === "Settings" && pressed(p) ? "scale-90" : ""}`}
                  style={{ background: bg as string }}
                >
                  {icon}
                </span>
                <span className="text-[10.5px] font-medium text-white">{label as string}</span>
              </div>
            ))}
          </div>
        </div>
      ),
    },
    {
      ms: 3400,
      bg: "#f4f4f6",
      caption: {
        en: "Tap Connections. (Pixel and other phones: Network & internet.)",
        ar: "اضغط «الاتصالات». (في هواتف Pixel وغيرها: «الشبكة والإنترنت».)",
      },
      render: (p) => (
        <div className="h-full bg-[#f4f4f6]">
          <p className="px-5 pb-4 pt-8 text-[24px] font-semibold text-[#111]">Settings</p>
          <AGroup>
            <Row tone="android" icon={<Icon bg="#3b82f6"><Wifi className="size-4" /></Icon>} label="Connections" sub="Wi-Fi • Bluetooth • SIM manager" hl pressed={pressed(p)} />
            <Row tone="android" icon={<Icon bg="#14b8a6"><Smartphone className="size-4" /></Icon>} label="Connected devices" sub="Quick Share • Android Auto" />
          </AGroup>
          <div className="h-3" />
          <AGroup>
            <Row tone="android" icon={<Icon bg="#f97316"><Bell className="size-4" /></Icon>} label="Notifications" sub="Status bar • Do not disturb" />
            <Row tone="android" icon={<Icon bg="#a855f7"><Volume2 className="size-4" /></Icon>} label="Sounds and vibration" sub="Sound mode • Ringtone" />
          </AGroup>
        </div>
      ),
    },
    {
      ms: 3400,
      bg: "#f4f4f6",
      caption: { en: "Scroll down and tap More connection settings.", ar: "مرّر للأسفل واضغط «المزيد من إعدادات الاتصال»." },
      render: (p) => (
        <div className="h-full bg-[#f4f4f6]">
          <AndroidNav title="Connections" />
          <AGroup>
            {["Wi-Fi", "Bluetooth", "NFC and contactless payments", "Flight mode", "SIM manager", "Mobile networks", "Data usage", "Mobile Hotspot and Tethering"].map((l) => (
              <Row key={l} tone="android" label={l} />
            ))}
          </AGroup>
          <div className="h-3" />
          <AGroup>
            <Row tone="android" label="More connection settings" hl pressed={pressed(p)} />
          </AGroup>
        </div>
      ),
    },
    {
      ms: 3200,
      bg: "#f4f4f6",
      caption: { en: "Tap Private DNS.", ar: "اضغط «DNS الخاص»." },
      render: (p) => (
        <div className="h-full bg-[#f4f4f6]">
          <AndroidNav title="More connection settings" />
          <AGroup>
            <Row tone="android" label="Nearby device scanning" />
            <Row tone="android" label="Printing" />
            <Row tone="android" label="VPN" sub="Not connected" />
            <Row tone="android" label="Private DNS" sub="Automatic" hl pressed={pressed(p)} />
            <Row tone="android" label="Ethernet" />
          </AGroup>
        </div>
      ),
    },
    {
      ms: 3200,
      bg: "#8c8c8c",
      caption: { en: "Choose Private DNS provider hostname.", ar: "اختر «اسم مضيف مزوّد DNS الخاص»." },
      render: (p) => <PrivateDnsDialog host="" selected={p > TAP_AT ? "host" : "auto"} hlChoice pressed={pressed(p)} />,
    },
    {
      ms: 4200,
      bg: "#8c8c8c",
      caption: { en: "Paste the SAQR hostname, then tap Save.", ar: "الصق اسم مضيف صقر، ثم اضغط «حفظ»." },
      render: (p) => {
        const typed = host.slice(0, Math.round(Math.min(1, p / 0.5) * host.length));
        return <PrivateDnsDialog host={typed} selected="host" hlSave pressed={p > TAP_AT + 0.05 && p < TAP_AT + 0.22} />;
      },
    },
    {
      ms: 3600,
      bg: "#f4f4f6",
      tap: false,
      caption: {
        en: "Done. Scam sites are now blocked in every app, even with SAQR closed.",
        ar: "تم. أصبحت مواقع الاحتيال محظورة في كل التطبيقات، حتى مع إغلاق صقر.",
      },
      render: () => (
        <div className="h-full bg-[#f4f4f6]">
          <AndroidNav title="More connection settings" />
          <AGroup>
            <Row tone="android" label="VPN" sub="Not connected" />
            <Row tone="android" label="Private DNS" sub={host} hl />
          </AGroup>
          <Done text="SAQR shield is on" />
        </div>
      ),
    },
  ];
}

function PrivateDnsDialog({ host, selected, hlChoice, hlSave, pressed }: {
  host: string; selected: "auto" | "host"; hlChoice?: boolean; hlSave?: boolean; pressed?: boolean;
}) {
  const radio = (on: boolean) => (
    <span className={`grid size-4 shrink-0 place-items-center rounded-full border-2 ${on ? "border-[#2563eb]" : "border-[#999]"}`}>
      {on && <span className="size-2 rounded-full bg-[#2563eb]" />}
    </span>
  );
  return (
    <div className="flex h-full items-end bg-black/45 p-3 pb-6">
      <div className="w-full rounded-3xl bg-white p-4">
        <p className="text-[16px] font-semibold text-[#111]">Private DNS</p>
        <div className="mt-3 space-y-1 text-[13px] text-[#111]">
          <p className="flex items-center gap-3 py-1.5">{radio(false)} Off</p>
          <p className="flex items-center gap-3 py-1.5">{radio(selected === "auto")} Automatic</p>
          <p data-hl={hlChoice ? "" : undefined} className={`flex items-center gap-3 rounded-lg py-1.5 transition-colors ${hlChoice && pressed ? "bg-black/10" : ""}`}>
            {radio(selected === "host")} Private DNS provider hostname
          </p>
        </div>
        {selected === "host" && (
          <div className="mt-2 rounded-t-md border-b-2 border-[#2563eb] bg-[#f4f6fb] px-2 py-2 font-mono text-[12px] text-[#111]" dir="ltr">
            {host || <span className="text-[#999]">Enter hostname of DNS provider</span>}
            {host && <span className="ms-px inline-block h-3.5 w-px animate-pulse bg-[#2563eb] align-middle" />}
          </div>
        )}
        <div className="mt-4 flex justify-end gap-6 text-[13px] font-semibold text-[#2563eb]">
          <span>Cancel</span>
          <span data-hl={hlSave ? "" : undefined} className={`rounded-md px-1 transition-colors ${hlSave && pressed ? "bg-[#2563eb]/15" : ""}`}>Save</span>
        </div>
      </div>
    </div>
  );
}

function Done({ text }: { text: string }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12, scale: 0.96 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ delay: 0.5, duration: 0.45, ease: EASE }}
      className="mx-6 mt-8 flex items-center gap-3 rounded-2xl bg-[#0b192c] p-3 text-white shadow-lg"
    >
      <span className="grid size-9 place-items-center rounded-xl bg-emerald-600"><ShieldCheck className="size-5" /></span>
      <span className="text-[13px] font-bold">{text}</span>
      <Check className="ms-auto size-4 text-emerald-400" />
    </motion.div>
  );
}

/* ------------------------------------------------------------------ iPhone scenes */

function iosScenes(): Scene[] {
  const pressed = (p: number) => p > TAP_AT && p < TAP_AT + 0.18;
  const profile = "SAQR-INTEL Citizen DNS Shield";
  return [
    {
      ms: 3400,
      bg: "#f3ecdf",
      caption: {
        en: "In Safari on the iPhone, tap Download iPhone DNS Profile on the SAQR page.",
        ar: "في سفاري على الآيفون، اضغط «تنزيل ملف DNS للآيفون» في صفحة صقر.",
      },
      render: (p) => (
        <div className="flex h-full flex-col bg-[#f3ecdf]">
          <div className="mx-3 mt-2 rounded-xl bg-white/80 px-3 py-1.5 text-center text-[11px] text-[#333]" dir="ltr">
            <Lock className="me-1 inline size-3" />saqr-intel.vercel.app
          </div>
          <div className="m-3 rounded-2xl bg-[#faf6ee] p-3 shadow-sm ring-1 ring-[#e0d4bf]">
            <p className="text-[13px] font-extrabold text-[#0b192c]">Activate System-Wide Background Shield</p>
            <p className="mt-1 text-[11px] leading-snug text-[#2b4568]">One-time setup. Your phone then checks every website in every app.</p>
            <span
              data-hl=""
              className={`mt-3 flex items-center justify-center gap-2 rounded-xl bg-[#0b192c] py-2.5 text-[12px] font-bold text-white transition-transform duration-150 ${pressed(p) ? "scale-95" : ""}`}
            >
              <Download className="size-3.5" /> Download iPhone DNS Profile
            </span>
          </div>
        </div>
      ),
    },
    {
      ms: 3200,
      bg: "#999999",
      caption: { en: "Safari asks to download a configuration profile: tap Allow.", ar: "يطلب سفاري تنزيل ملف تعريف: اضغط «سماح»." },
      render: (p) => (
        <IosAlert
          title="This website is trying to download a configuration profile. Do you want to allow this?"
          buttons={["Ignore", "Allow"]}
          hl="Allow"
          pressed={pressed(p)}
        />
      ),
    },
    {
      ms: 3000,
      bg: "#999999",
      caption: { en: "The profile is downloaded. Tap Close.", ar: "تم تنزيل الملف. اضغط «إغلاق»." },
      render: (p) => (
        <IosAlert title="Profile Downloaded" body="Review the profile in the Settings app if you want to install it." buttons={["Close"]} hl="Close" pressed={pressed(p)} />
      ),
    },
    {
      ms: 3400,
      bg: "#f2f2f7",
      caption: { en: "Open the Settings app and tap General.", ar: "افتح تطبيق الإعدادات واضغط «عام»." },
      render: (p) => (
        <div className="h-full bg-[#f2f2f7]">
          <IosNav title="Settings" />
          <Group>
            <Row icon={<Icon bg="#ff9500"><Smartphone className="size-4" /></Icon>} label="Profile Downloaded" />
          </Group>
          <div className="h-4" />
          <Group>
            <Row icon={<Icon bg="#0a84ff"><Wifi className="size-4" /></Icon>} label="Wi-Fi" value="Home" />
            <Row icon={<Icon bg="#0a84ff"><Bluetooth className="size-4" /></Icon>} label="Bluetooth" value="On" />
          </Group>
          <div className="h-4" />
          <Group>
            <Row icon={<Icon bg="#8e8e93"><Settings className="size-4" /></Icon>} label="General" hl pressed={pressed(p)} />
            <Row icon={<Icon bg="#ff3b30"><Bell className="size-4" /></Icon>} label="Notifications" />
          </Group>
        </div>
      ),
    },
    {
      ms: 3400,
      bg: "#f2f2f7",
      caption: { en: "Scroll down and tap VPN & Device Management.", ar: "مرّر للأسفل واضغط «VPN وإدارة الجهاز»." },
      render: (p) => (
        <div className="h-full bg-[#f2f2f7]">
          <IosNav title="General" back="Settings" />
          <Group>
            {["About", "Software Update", "AirDrop", "iPhone Storage", "Background App Refresh"].map((l) => <Row key={l} label={l} />)}
          </Group>
          <div className="h-4" />
          <Group>
            <Row label="Date & Time" />
            <Row label="Keyboard" />
            <Row label="VPN & Device Management" hl pressed={pressed(p)} />
          </Group>
        </div>
      ),
    },
    {
      ms: 3200,
      bg: "#f2f2f7",
      caption: { en: `Under Downloaded Profile, tap ${profile}.`, ar: `تحت «الملف الذي تم تنزيله»، اضغط ${profile}.` },
      render: (p) => (
        <div className="h-full bg-[#f2f2f7]">
          <IosNav title="VPN & Device Management" back="General" />
          <Group>
            <Row label="VPN" value="Not Connected" />
            <Row label="DNS" value="Automatic" />
          </Group>
          <p className="px-6 pb-1 pt-4 text-[11px] uppercase text-[#6d6d72]">Downloaded profile</p>
          <Group>
            <Row icon={<Icon bg="#0b192c"><ShieldCheck className="size-4 text-[#c5a572]" /></Icon>} label={profile} sub="SAQR-INTEL" hl pressed={pressed(p)} />
          </Group>
        </div>
      ),
    },
    {
      ms: 3200,
      bg: "#f2f2f7",
      caption: { en: "Tap Install at the top right.", ar: "اضغط «تثبيت» أعلى اليمين." },
      render: (p) => (
        <div className="h-full bg-[#f2f2f7]">
          <div className="flex items-center justify-between px-4 pb-2 pt-3 text-[13px]">
            <span className="text-[#0a84ff]">Cancel</span>
            <span className="font-semibold text-black">Install Profile</span>
            <span data-hl="" className={`rounded-md px-1 font-semibold text-[#0a84ff] transition-colors ${pressed(p) ? "bg-[#0a84ff]/15" : ""}`}>Install</span>
          </div>
          <div className="mx-3 mt-3 rounded-xl bg-white p-4 text-center">
            <span className="mx-auto grid size-12 place-items-center rounded-2xl bg-[#0b192c]"><ShieldCheck className="size-6 text-[#c5a572]" /></span>
            <p className="mt-2 text-[14px] font-semibold text-black">{profile}</p>
            <p className="text-[11px] text-[#6d6d72]">SAQR-INTEL · DNS Settings</p>
          </div>
        </div>
      ),
    },
    {
      ms: 3000,
      bg: "#f2f2f7",
      tap: false,
      caption: { en: "Enter your iPhone passcode.", ar: "أدخل رمز قفل الآيفون." },
      render: (p) => {
        const filled = Math.min(6, Math.floor((p / 0.85) * 6));
        return (
          <div className="flex h-full flex-col items-center bg-[#f2f2f7] pt-14">
            <p className="text-[15px] font-semibold text-black">Enter Passcode</p>
            <div className="mt-5 flex gap-3" data-hl="">
              {Array.from({ length: 6 }, (_, i) => (
                <span key={i} className={`size-3 rounded-full border border-black transition-colors duration-100 ${i < filled ? "bg-black" : ""}`} />
              ))}
            </div>
            <div className="mt-10 grid grid-cols-3 gap-x-7 gap-y-4">
              {"123456789".split("").map((n) => (
                <span key={n} className="grid size-14 place-items-center rounded-full bg-[#e5e5ea] text-[22px] text-black">{n}</span>
              ))}
            </div>
          </div>
        );
      },
    },
    {
      ms: 3200,
      bg: "#999999",
      caption: { en: "Tap Install again to confirm.", ar: "اضغط «تثبيت» مرة أخرى للتأكيد." },
      render: (p) => (
        <div className="flex h-full items-end bg-black/40">
          <div className="w-full rounded-t-2xl bg-[#f2f2f7] p-2 pb-6">
            <div className="rounded-xl bg-white p-3 text-center text-[12px] text-[#3c3c43]">Install Profile — the profile will change the DNS settings of this iPhone.</div>
            <span data-hl="" className={`mt-2 block rounded-xl bg-white py-3 text-center text-[15px] font-semibold text-[#ff3b30] transition-colors ${pressed(p) ? "bg-[#e5e5ea]" : ""}`}>Install</span>
            <span className="mt-2 block rounded-xl bg-white py-3 text-center text-[15px] font-semibold text-[#0a84ff]">Cancel</span>
          </div>
        </div>
      ),
    },
    {
      ms: 3400,
      bg: "#f2f2f7",
      caption: {
        en: "Back in VPN & Device Management, open DNS and make sure SAQR is ticked.",
        ar: "في «VPN وإدارة الجهاز»، افتح «DNS» وتأكد من تحديد صقر.",
      },
      render: (p) => (
        <div className="h-full bg-[#f2f2f7]">
          <IosNav title="DNS" back="VPN & Device Management" />
          <Group>
            <div className="flex items-center gap-3 px-4 py-2.5 text-[13px] text-black">
              <span className="flex-1">Automatic</span>
            </div>
            <div data-hl="" className={`flex items-center gap-3 px-4 py-2.5 text-[13px] text-black transition-colors ${pressed(p) ? "bg-black/10" : ""}`}>
              <span className="flex-1">{profile}</span>
              {p > TAP_AT && <Check className="size-4 text-[#0a84ff]" />}
            </div>
          </Group>
        </div>
      ),
    },
    {
      ms: 3600,
      bg: "#f2f2f7",
      tap: false,
      caption: {
        en: "Done. Scam sites are now blocked in Safari, WhatsApp and every app.",
        ar: "تم. أصبحت مواقع الاحتيال محظورة في سفاري وواتساب وكل التطبيقات.",
      },
      render: () => (
        <div className="h-full bg-[#f2f2f7]">
          <IosNav title="VPN & Device Management" back="General" />
          <Group>
            <Row label="DNS" value={profile} hl />
          </Group>
          <Done text="SAQR shield is on" />
        </div>
      ),
    },
  ];
}

function IosAlert({ title, body, buttons, hl, pressed }: { title: string; body?: string; buttons: string[]; hl: string; pressed: boolean }) {
  return (
    <div className="grid h-full place-items-center bg-black/40 px-8">
      <div className="w-full overflow-hidden rounded-2xl bg-[#f2f2f7]/95 text-center backdrop-blur">
        <div className="px-4 py-4">
          <p className="text-[13px] font-semibold leading-snug text-black">{title}</p>
          {body && <p className="mt-1 text-[11.5px] leading-snug text-[#3c3c43]">{body}</p>}
        </div>
        <div className={`grid border-t border-[#c6c6c8] ${buttons.length > 1 ? "grid-cols-2 [&>*+*]:border-s [&>*+*]:border-[#c6c6c8]" : ""}`}>
          {buttons.map((b) => (
            <span
              key={b}
              data-hl={b === hl ? "" : undefined}
              className={`py-2.5 text-[14px] text-[#0a84ff] transition-colors ${b === hl ? "font-semibold" : ""} ${b === hl && pressed ? "bg-black/10" : ""}`}
            >
              {b}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ the player */

function useSceneClock(scenes: Scene[], playing: boolean, onEnd: () => void) {
  const [index, setIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const state = useRef({ index: 0, elapsed: 0, last: 0 });

  const jump = useCallback((i: number) => {
    state.current = { index: i, elapsed: 0, last: 0 };
    setIndex(i);
    setProgress(0);
  }, []);

  useEffect(() => {
    if (!playing) return;
    let raf = 0;
    const tick = (now: number) => {
      const s = state.current;
      if (s.last) s.elapsed += now - s.last;
      s.last = now;
      const ms = scenes[s.index].ms;
      if (s.elapsed >= ms) {
        if (s.index >= scenes.length - 1) {
          setProgress(1);
          onEnd();
          return;
        }
        s.index += 1;
        s.elapsed = 0;
        setIndex(s.index);
      }
      setProgress(Math.min(1, s.elapsed / scenes[s.index].ms));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      state.current.last = 0;
    };
  }, [playing, scenes, onEnd]);

  return { index, progress, jump };
}

/** Position of the highlighted element inside the screen (offsets ignore the slide transform). */
function measure(root: HTMLElement | null, index: number): { x: number; y: number; w: number; h: number } | null {
  const scene = root?.querySelector<HTMLElement>(`[data-scene="${index}"]`);
  const el = scene?.querySelector<HTMLElement>("[data-hl]");
  if (!root || !el) return null;
  let x = 0;
  let y = 0;
  let node: HTMLElement | null = el;
  while (node && node !== root) {
    x += node.offsetLeft;
    y += node.offsetTop;
    node = node.offsetParent as HTMLElement | null;
  }
  return { x, y, w: el.offsetWidth, h: el.offsetHeight };
}

function Player({ scenes, platformLabel }: { scenes: Scene[]; platformLabel: string }) {
  const { lang } = useLang();
  const reduce = useReducedMotion();
  const [playing, setPlaying] = useState(true);
  const [ended, setEnded] = useState(false);
  const onEnd = useCallback(() => {
    setPlaying(false);
    setEnded(true);
  }, []);
  const { index, progress, jump } = useSceneClock(scenes, playing, onEnd);
  const screen = useRef<HTMLDivElement>(null);
  const [ring, setRing] = useState<{ x: number; y: number; w: number; h: number } | null>(null);
  const scene = scenes[index];

  // Measure once the incoming screen has mounted (offsets ignore its slide-in transform).
  useEffect(() => {
    const id = requestAnimationFrame(() => setRing(measure(screen.current, index)));
    return () => cancelAnimationFrame(id);
  }, [index]);

  const replay = () => {
    jump(0);
    setEnded(false);
    setPlaying(true);
  };
  const toggle = () => {
    if (ended) replay();
    else setPlaying((v) => !v);
  };
  const showTap = scene.tap !== false && ring && progress > TAP_AT && progress < TAP_AT + 0.3;
  const total = Math.round(scenes.reduce((a, s) => a + s.ms, 0) / 1000);

  return (
    <div className="flex flex-col items-center gap-4">
      {/* phone */}
      <div className="w-[272px] rounded-[2.6rem] border-[9px] border-navy-900 bg-navy-900 shadow-[0_24px_60px_-20px_rgba(11,25,44,0.6)] dark:border-black">
        <div className="relative h-[520px] overflow-hidden rounded-[2rem] bg-white" ref={screen} dir="ltr">
          <span aria-hidden className="absolute left-1/2 top-1.5 z-10 h-4 w-16 -translate-x-1/2 rounded-full bg-black" />
          <AnimatePresence initial={false} mode="popLayout">
            <motion.div
              key={index}
              data-scene={index}
              className="absolute inset-0 pt-6"
              style={{ background: scene.bg ?? "#f2f2f7" }}
              initial={reduce ? { opacity: 0 } : { x: "35%", opacity: 0 }}
              animate={{ x: 0, opacity: 1, transition: { duration: 0.36, ease: EASE } }}
              exit={reduce ? { opacity: 0 } : { x: "-18%", opacity: 0, transition: { duration: 0.22, ease: [0.4, 0, 1, 1] } }}
            >
              {scene.render(progress)}
            </motion.div>
          </AnimatePresence>

          {/* highlight ring: glides from the last option to the next one */}
          {ring && (
            <motion.div
              aria-hidden
              className="pointer-events-none absolute z-20 rounded-xl border-[2.5px] border-emerald-500 shadow-[0_0_0_4px_rgba(16,185,129,0.25),0_6px_20px_-4px_rgba(16,185,129,0.55)]"
              style={{ left: 0, top: 0 }}
              initial={false}
              animate={{ x: ring.x - 4, y: ring.y - 4, width: ring.w + 8, height: ring.h + 8, opacity: 1 }}
              transition={{ duration: reduce ? 0 : 0.45, ease: EASE, delay: reduce ? 0 : 0.2 }}
            >
              {!reduce && playing && <span className="absolute inset-0 animate-[saqr-hl_1.2s_ease-out_infinite] rounded-xl border-2 border-emerald-400" />}
            </motion.div>
          )}

          {/* tap ripple */}
          <AnimatePresence>
            {showTap && ring && (
              <motion.span
                key={`tap-${index}`}
                aria-hidden
                className="pointer-events-none absolute z-30 size-10 rounded-full bg-white/70 ring-2 ring-navy-900/40"
                style={{ left: ring.x + ring.w / 2 - 20, top: ring.y + ring.h / 2 - 20 }}
                initial={{ scale: 0.3, opacity: 0.9 }}
                animate={{ scale: reduce ? 1 : 1.5, opacity: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.6, ease: EASE }}
              />
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* caption: what to do on this screen */}
      <div className="min-h-[3.25rem] w-full max-w-sm text-center" aria-live="polite">
        <p className="text-[11px] font-bold uppercase tracking-wider text-emerald-700 dark:text-emerald-400">
          {platformLabel} · {lang === "ar" ? "الخطوة" : "Step"} {index + 1}/{scenes.length}
        </p>
        <p className="mt-1 text-sm font-semibold leading-snug text-ink">{scene.caption[lang]}</p>
      </div>

      {/* controls */}
      <div className="flex w-full max-w-sm items-center gap-3">
        <button
          type="button"
          onClick={toggle}
          aria-label={ended ? (lang === "ar" ? "إعادة التشغيل" : "Replay") : playing ? (lang === "ar" ? "إيقاف مؤقت" : "Pause") : (lang === "ar" ? "تشغيل" : "Play")}
          className="press grid size-10 shrink-0 place-items-center rounded-full bg-navy-900 text-white hover:bg-navy-800 dark:bg-white dark:text-navy-900"
        >
          {ended ? <RotateCcw className="size-4" /> : playing ? <Pause className="size-4" /> : <Play className="size-4 translate-x-px" />}
        </button>
        <div className="flex flex-1 gap-1" dir="ltr">
          {scenes.map((s, i) => (
            <button
              key={i}
              type="button"
              aria-label={`${lang === "ar" ? "الخطوة" : "Step"} ${i + 1}`}
              onClick={() => {
                jump(i);
                setEnded(false);
              }}
              className="group h-6 flex-1 py-2.5"
            >
              <span className="block h-1 overflow-hidden rounded-full bg-line group-hover:bg-ink-soft/40">
                <span
                  className="block h-full rounded-full bg-emerald-600"
                  style={{ width: i < index ? "100%" : i === index ? `${progress * 100}%` : "0%" }}
                />
              </span>
            </button>
          ))}
        </div>
        <span className="shrink-0 text-xs tabular-nums text-ink-soft/80" dir="ltr">~{total}s</span>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ button + pop-up */

export function SetupVideoButton({ platform, host }: { platform: "android" | "ios"; host: string }) {
  const { lang } = useLang();
  const [open, setOpen] = useState(false);
  const label = platform === "android" ? "Android" : "iPhone";
  // Built when the pop-up opens, so the video types the hostname that is in the box right now.
  const scenes = useMemo(() => (open ? (platform === "android" ? androidScenes(host) : iosScenes()) : null), [open, platform, host]);
  const close = () => setOpen(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="press inline-flex items-center gap-2 rounded-full bg-surface px-3.5 py-2 text-xs font-bold text-ink shadow-sm ring-1 ring-line hover:bg-muted"
      >
        <span className="grid size-5 place-items-center rounded-full bg-emerald-700 text-white">
          <Play className="size-2.5 translate-x-px fill-current" />
        </span>
        {lang === "ar" ? `شاهد فيديو الإعداد على ${platform === "android" ? "أندرويد" : "الآيفون"}` : `Watch the ${label} setup video`}
      </button>
      <Modal
        open={open}
        onClose={close}
        title={lang === "ar" ? `إعداد درع صقر على ${platform === "android" ? "أندرويد" : "الآيفون"}` : `Set up the SAQR shield on ${label}`}
      >
        {open && scenes && <Player key={platform} scenes={scenes} platformLabel={label} />}
      </Modal>
    </>
  );
}
