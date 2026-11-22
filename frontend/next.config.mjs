/** @type {import('next').NextConfig} */
const BACKEND = process.env.SAQR_BACKEND_URL ?? "http://127.0.0.1:8000";

const nextConfig = {
  // Lets phones load the dev server through a Cloudflare quick tunnel or the local Wi-Fi network.
  allowedDevOrigins: ["*.trycloudflare.com", "192.168.*.*", "10.*.*.*", "172.*.*.*"],
  turbopack: {
    rules: {
      "*.css": { loaders: ["@tailwindcss/turbopack"], as: "*.css" },
    },
  },
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${BACKEND}/api/:path*` },
      // Live feed for the Crowd-Shield radar; same-origin so it also works through HTTPS tunnels.
      { source: "/ws/:path*", destination: `${BACKEND}/ws/:path*` },
    ];
  },
  experimental: {
    // Deep scans (sandbox + AI) can take longer than the 30 s default proxy timeout.
    proxyTimeout: 120_000,
  },
};

export default nextConfig;
