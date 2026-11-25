"use client";

import Link from "next/link";
import { ChevronRight, Sparkles } from "lucide-react";

import { SeverityBadge, StatusBadge } from "@/components/common";
import type { Alert, Severity } from "@/lib/api";
import { deviceName, formatTime, timeAgo } from "@/lib/format";
import { cn } from "@/lib/utils";

const EDGE: Record<Severity, string> = {
  critical: "border-l-sev-critical",
  high: "border-l-sev-high",
  medium: "border-l-sev-medium",
  low: "border-l-sev-low",
};

/** Alerts as plain-language cards: what happened, to which device, how urgent. */
export function AlertList({ alerts, now, showSummary = true }: { alerts: Alert[]; now?: number; showSummary?: boolean }) {
  return (
    <ul className="space-y-3">
      {alerts.map((a) => (
        <li key={a.id}>
          <Link
            href={`/alert/?id=${a.id}`}
            className={cn(
              "group flex items-start gap-3 rounded-lg border border-l-4 bg-card p-4 transition-colors hover:bg-accent/50",
              EDGE[a.severity],
              a.status === "resolved" && "opacity-70",
            )}
          >
            <div className="min-w-0 flex-1 space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={a.severity} />
                {a.status !== "open" && <StatusBadge status={a.status} />}
                {a.detector === "ml" && (
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-ai">
                    <Sparkles className="size-3.5" /> ML detection
                  </span>
                )}
                {(a.evidence?.ml as { agrees?: boolean } | undefined)?.agrees && (
                  <span className="inline-flex items-center gap-1 text-xs font-medium text-ai">
                    <Sparkles className="size-3.5" /> Rules + ML agree
                  </span>
                )}
                <span className="text-xs text-muted-foreground" title={formatTime(a.ts_raised ?? a.ts_last)}>
                  {timeAgo(a.ts_raised ?? a.ts_last, now)}
                </span>
              </div>
              <p className="font-semibold leading-snug">{a.headline ?? a.title}</p>
              {showSummary && a.summary && (
                <p className="line-clamp-2 text-sm leading-relaxed text-muted-foreground">{a.summary}</p>
              )}
              {a.device_ip && !a.headline && (
                <p className="text-xs text-muted-foreground">{deviceName(a.device, a.device_ip)}</p>
              )}
            </div>
            <ChevronRight className="mt-1 size-5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
          </Link>
        </li>
      ))}
    </ul>
  );
}
