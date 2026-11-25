import type { Severity } from "./api";

export function formatBytes(n: number | null | undefined): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
  const v = n / 1024 ** i;
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export function formatTime(ts: number | null | undefined): string {
  if (!ts) return "–";
  return new Date(ts * 1000).toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatClock(ts: number | null | undefined): string {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** Relative to a reference time (the sensor's event clock, so replays read naturally). */
export function timeAgo(ts: number | null | undefined, now: number = Date.now() / 1000): string {
  if (!ts) return "–";
  const s = Math.max(0, now - ts);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function formatDuration(s: number): string {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export const KIND_LABELS: Record<string, string> = {
  port_scan: "Port scan",
  host_sweep: "Network sweep",
  syn_flood: "SYN flood",
  brute_force: "Password guessing",
  phishing_domain: "Phishing site",
  scam_domain: "Scam site",
  malware_domain: "Malware site",
  c2_domain: "Malware control server",
  c2_ip: "Malware control server",
  lab_domain: "Test phishing site",
  dga: "Malware-style address lookups",
  dns_tunnel: "Data hidden in DNS",
  beaconing: "Regular check-ins",
  new_fingerprint: "New software",
  unusual_upload: "Unusual upload",
  unusual_destinations: "Unusual activity",
  ml_dos: "AI detector: flooding",
  ml_scan: "AI detector: scanning",
  ml_brute_force: "AI detector: password guessing",
  ml_web_attack: "AI detector: web attack",
  ml_botnet: "AI detector: botnet",
};

export function kindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind.replace(/_/g, " ");
}

/** "evidence_key" -> "Evidence key"; unit suffixes become units ("duration_s" -> "Duration"). */
export function humanize(key: string): string {
  const s = key.replace(/_s$/, "").replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Unit for an evidence value, from its key. */
export function unitFor(key: string): string {
  if (key.endsWith("_s")) return " s";
  if (key.endsWith("_per_second")) return " /s";
  if (key.includes("bytes")) return " bytes";
  return "";
}

/** A friendly name for a device that has no hostname: its type, never the bare IP twice. */
export function deviceName(d: { hostname?: string | null; kind?: string | null } | null | undefined, ip?: string | null): string {
  if (d?.hostname) return d.hostname;
  if (d?.kind) return d.kind.replace(/\s*\(private MAC\)/, "");
  return ip ?? "Unknown device";
}

/** Severity in words a non-expert acts on. */
export const SEVERITY_WORD: Record<Severity, string> = {
  critical: "Act now",
  high: "Urgent",
  medium: "Check soon",
  low: "For your info",
};
