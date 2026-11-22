import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "SAQR-INTEL Citizen Shield",
    short_name: "SAQR Verify",
    description: "Share any suspicious link or Google Maps listing to SAQR Verify for an instant Abu Dhabi Police security verdict.",
    id: "/citizen",
    start_url: "/citizen",
    scope: "/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#0B192C",
    theme_color: "#0B192C",
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
