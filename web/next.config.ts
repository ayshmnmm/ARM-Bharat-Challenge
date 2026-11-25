import type { NextConfig } from "next";

const dev = process.env.NODE_ENV === "development";

// Production: static export; the Pi serves plain files from FastAPI and no Node.js process runs.
// Development (`npm run dev`): pages from the Next.js dev server, data proxied to a local FastAPI
// on loopback (NETWATCH_DEV_API, default 127.0.0.1:8089). Both stay off eth0.
const nextConfig: NextConfig = dev
  ? {
      trailingSlash: true,
      images: { unoptimized: true },
      poweredByHeader: false,
      allowedDevOrigins: ["192.168.1.1"],
      agentRules: false, // don't write AGENTS.md into the repo
      // FastAPI routes have no trailing slash; don't redirect /api/x to /api/x/ before proxying
      skipTrailingSlashRedirect: true,
      async rewrites() {
        const api = process.env.NETWATCH_DEV_API ?? "http://127.0.0.1:8089";
        return [{ source: "/api/:path*", destination: `${api}/api/:path*` }];
      },
    }
  : {
      output: "export",
      trailingSlash: true,
      images: { unoptimized: true },
      poweredByHeader: false,
    };

export default nextConfig;
