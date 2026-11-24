import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Saqr — Abu Dhabi Anti-Scam Shield",
    short_name: "Saqr",
    description: "Share any suspicious link, message or Google Maps listing to Saqr for an instant scam verdict.",
    id: "/citizen",
    start_url: "/citizen",
    scope: "/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#F7F5F0",
    theme_color: "#F7F5F0",
    lang: "en",
    dir: "auto",
    categories: ["security", "utilities", "government"],
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: "/icons/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ],
    share_target: {
      action: "/citizen",
      method: "GET",
      params: { title: "title", text: "text", url: "url" },
    },
  };
}
