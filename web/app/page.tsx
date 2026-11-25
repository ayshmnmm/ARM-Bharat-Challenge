"use client";

import Link from "next/link";
import { ArrowRight, ShieldAlert, ShieldCheck } from "lucide-react";

import { AlertList } from "@/components/alert-list";
import { Empty, ErrorBlock, LoadingBlock } from "@/components/common";
import { Pipeline } from "@/components/pipeline";
import { WeeklySummaryCard } from "@/components/weekly-summary";
import { Button } from "@/components/ui/button";
import { useApi, type Overview, type Severity } from "@/lib/api";
import { formatTime, SEVERITIES, SEVERITY_WORD } from "@/lib/format";
import { cn } from "@/lib/utils";

const TONE: Record<Severity | "ok", string> = {
  critical: "border-sev-critical/40 bg-sev-critical/8",
  high: "border-sev-high/40 bg-sev-high/8",
  medium: "border-sev-medium/50 bg-sev-medium/10",
  low: "border-sev-low/40 bg-sev-low/8",
  ok: "border-ok/40 bg-ok/8",
};
const ICON_TONE: Record<Severity | "ok", string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  ok: "text-ok",
};

function StatusBanner({ data }: { data: Overview }) {
  const open = SEVERITIES.reduce((n, s) => n + data.alerts_open[s], 0);
  const worst = SEVERITIES.find((s) => data.alerts_open[s] > 0);
  const tone = worst ?? "ok";
  const Icon = open ? ShieldAlert : ShieldCheck;
  const breakdown = SEVERITIES.filter((s) => data.alerts_open[s] > 0)
    .map((s) => `${data.alerts_open[s]} ${SEVERITY_WORD[s].toLowerCase()}`)
    .join(", ");
  return (
    <section className={cn("flex flex-col gap-4 rounded-2xl border p-6 sm:flex-row sm:items-center sm:p-8", TONE[tone])}>
      <Icon className={cn("size-14 shrink-0", ICON_TONE[tone])} aria-hidden />
      <div className="min-w-0 flex-1">
        <h1 className="text-2xl font-semibold tracking-tight text-balance sm:text-3xl">
          {open === 0 ? "Your network is safe" : `${open} thing${open > 1 ? "s" : ""} need${open > 1 ? "" : "s"} your attention`}
        </h1>
        <p className="mt-2 text-muted-foreground">
          {open === 0
            ? `${data.devices_total} device${data.devices_total === 1 ? "" : "s"} · no open alerts`
            : `${breakdown}.`}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {data.clock ? `Last activity ${formatTime(data.clock)}` : "Waiting for the first traffic"}
        </p>
      </div>
      {open > 0 && (
        <Button asChild size="lg" className="w-full sm:w-auto">
          <Link href="/alerts/">
            See what happened <ArrowRight className="size-4" />
          </Link>
        </Button>
      )}
    </section>
  );
}

export default function HomePage() {
  const { data, error, isLoading } = useApi<Overview>("/api/overview");

  if (error) return <ErrorBlock error={error} />;
  if (isLoading || !data) return <LoadingBlock rows={6} />;

  const open = data.recent_alerts.filter((a) => a.status === "open");
  const shown = (open.length ? open : data.recent_alerts).slice(0, 4);

  return (
    <div className="mx-auto max-w-4xl space-y-10">
      <StatusBanner data={data} />

      <section aria-labelledby="latest">
        <div className="mb-3 flex items-end justify-between gap-4">
          <h2 id="latest" className="text-lg font-semibold">
            {open.length ? "Needs your attention" : "Latest alerts"}
          </h2>
          <Link href="/alerts/" className="text-sm font-medium text-primary hover:underline">
            See all
          </Link>
        </div>
        {shown.length === 0 ? <Empty>No alerts</Empty> : <AlertList alerts={shown} now={data.clock} />}
      </section>

      <WeeklySummaryCard />

      <section aria-labelledby="how">
        <h2 id="how" className="mb-3 text-lg font-semibold">
          How NetWatch protects you
        </h2>
        <Pipeline data={data} />
        <Link href="/system/" className="mt-3 inline-block text-sm font-medium text-primary hover:underline">
          System details
        </Link>
      </section>
    </div>
  );
}
