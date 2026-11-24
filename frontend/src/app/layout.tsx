import type { Metadata, Viewport } from "next";
import { Barlow, Noto_Kufi_Arabic } from "next/font/google";
import { ThemeScript } from "@/components/ThemeScript";
import "./globals.css";

// Self-hosted at build time (no request to Google from the visitor). Wired to --font-sans / --font-arabic.
// Barlow: a DIN-like grotesk in the register of UAE road signs and the Abu Dhabi Police site's caps.
const barlow = Barlow({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700", "800"], variable: "--font-barlow", display: "swap" });
const kufi = Noto_Kufi_Arabic({ subsets: ["arabic"], variable: "--font-kufi", display: "swap" });

export const metadata: Metadata = {
  title: "SAQR-INTEL Citizen Shield",
  description: "Automatic anti-fraud protection for Abu Dhabi residents — no app install required.",
  applicationName: "SAQR Verify",
  appleWebApp: { capable: true, title: "SAQR Verify", statusBarStyle: "black-translucent" },
  icons: {
    icon: [
      { url: "/icons/icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/icons/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    apple: "/icons/icon-192.png",
  },
};

export const viewport: Viewport = {
  themeColor: "#0B192C",
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning className={`${barlow.variable} ${kufi.variable}`}>
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-dvh antialiased">{children}</body>
    </html>
  );
}
