"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, Check, CheckCheck, ChevronDown, CircleCheck, CircleMinus, RotateCcw, Sparkles } from "lucide-react";
import { Suspense } from "react";
import { toast } from "sonner";

import { ActionButtons } from "@/components/action-buttons";
import { Empty, ErrorBlock, LoadingBlock, SeverityBadge, StatusBadge } from "@/components/common";
import { Evidence } from "@/components/evidence";
import { Button } from "@/components/ui/button";
import { post, useApi, type AlertDetail, type AlertStatus, type Explanation, type Severity } from "@/lib/api";
import { deviceName, formatTime, SEVERITY_WORD } from "@/lib/format";
import { cn } from "@/lib/utils";

const RISK_TONE: Record<Severity, string> = {
  critical: "border-sev-critical/40 bg-sev-critical/8",
  high: "border-sev-high/40 bg-sev-high/8",
  medium: "border-sev-medium/50 bg-sev-medium/10",
  low: "border-sev-low/40 bg-sev-low/8",
};

/** Who wrote the explanation and how: the on-device AI claim, made checkable. */
function Provenance({ exp }: { exp: Explanation }) {
  if (exp.pending) {
    return (
      <p className="flex items-center gap-1.5 text-xs text-ai">
        <Sparkles className="size-3.5 animate-pulse" />
        Generating explanation…
      </p>
    );
  }
  if (exp.provider.startsWith("llama")) {
    const s = exp.stats;
    return (
      <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-ai">
        <Sparkles className="size-3.5" />
        <span className="font-medium">Llama 3.2 1B · on-device</span>
        <span className="text-muted-foreground">
          · {(exp.latency_ms / 1000).toFixed(0)} s{s?.decode_token_per_sec ? ` · ${s.decode_token_per_sec.toFixed(1)} tok/s` : ""} ·
          fact-checked
        </span>
      </p>
    );
  }
  return (
    <p className="text-xs text-muted-foreground">
      {exp.provider.includes("failed")
        ? "Template summary (LLM output failed fact check)"
        : "Template summary (LLM off)"}
    </p>
  );
}

function Section({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("space-y-2", className)}>
      <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">{title}</h2>
      {children}
    </section>
  );
}

function HowDecided({ a }: { a: AlertDetail }) {
  const exp = a.explanation;
  return (
    <details className="group rounded-xl border bg-card">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 p-4 font-semibold sm:p-5">
        <span>Detection details</span>
        <ChevronDown className="size-5 shrink-0 transition-transform group-open:rotate-180" />
      </summary>
      <div className="space-y-6 border-t p-4 sm:p-5">
        {a.criteria?.length > 0 && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Checks</h3>
            <ul className="divide-y rounded-lg border">
              {a.criteria.map((c) => (
                <li key={c.check} className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 p-3 sm:grid-cols-[auto_1fr_auto] sm:items-center">
                  {c.met ? (
                    <CircleCheck className="size-5 text-sev-high" aria-label="Check met" />
                  ) : (
                    <CircleMinus className="size-5 text-muted-foreground" aria-label="Not met" />
                  )}
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{c.check}</p>
                    <p className="text-xs text-muted-foreground">Rule: {c.rule}</p>
                  </div>
                  <p className="col-start-2 font-mono text-sm font-semibold break-words sm:col-start-3 sm:text-right">{c.observed}</p>
                </li>
              ))}
            </ul>
          </div>
        )}

        {exp.facts?.length > 0 && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">LLM input</h3>
            <ul className="space-y-1 rounded-lg bg-muted/60 p-3 text-sm leading-relaxed">
              {exp.facts.map((f) => (
                <li key={f}>• {f}</li>
              ))}
            </ul>
          </div>
        )}

        <div>
          <h3 className="mb-2 text-sm font-semibold">Raw evidence</h3>
          <Evidence evidence={a.evidence} />
        </div>
      </div>
    </details>
  );
}

function AlertView() {
  const id = useSearchParams().get("id");
  const { data: a, error, isLoading, mutate } = useApi<AlertDetail>(id ? `/api/alerts/${id}` : null);

  if (!id) return <Empty>No alert selected</Empty>;
  if (error) return <ErrorBlock error={error} />;
  if (isLoading || !a) return <LoadingBlock rows={6} />;

  const exp = a.explanation;

  async function setStatus(status: AlertStatus) {
    try {
      await post(`/api/alerts/${a!.id}/status`, { status });
      toast.success({ open: "Moved back to Needs attention", acknowledged: "Marked as seen", resolved: "Marked as dealt with" }[status]);
      mutate();
    } catch (e) {
      toast.error("Could not update the alert", { description: e instanceof Error ? e.message : String(e) });
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <Button asChild variant="ghost" size="sm" className="-ml-2 mb-4">
        <Link href="/alerts/">
          <ArrowLeft className="size-4" /> All alerts
        </Link>
      </Button>

      <header className="mb-6">
        <div className="mb-3 flex flex-wrap items-center gap-2">
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
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-balance sm:text-3xl">{a.headline ?? a.title}</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {formatTime(a.ts_first)}
          {a.count > 1 && ` · happened ${a.count} times`}
          {a.device_ip && (
            <>
              {" · "}
              <Link href={`/device/?ip=${a.device_ip}`} className="font-medium text-foreground underline underline-offset-4">
                {deviceName(a.device, a.device_ip)}
              </Link>
            </>
          )}
        </p>
      </header>

      <div className="space-y-8 rounded-2xl border bg-card p-5 sm:p-7">
        <Section title="What happened">
          <p className="text-lg leading-relaxed text-pretty">{exp.summary}</p>
          <Provenance exp={exp} />
        </Section>

        <Section title="Why it matters">
          <p className="leading-relaxed">{exp.why}</p>
        </Section>

        <div className={cn("rounded-xl border p-4", RISK_TONE[a.severity])}>
          <p className="mb-1 text-sm font-semibold">How serious: {SEVERITY_WORD[a.severity]}</p>
          <p className="leading-relaxed first-letter:uppercase">{exp.risk}</p>
        </div>

        <Section title="What you should do">
          <ol className="space-y-3">
            {exp.actions.map((s, i) => (
              <li key={s} className="flex gap-3 leading-relaxed">
                <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary text-sm font-semibold text-primary-foreground">
                  {i + 1}
                </span>
                <span className="pt-0.5">{s}</span>
              </li>
            ))}
          </ol>
          {a.actions.length > 0 && (
            <div className="pt-3">
              <p className="mb-2 text-xs text-muted-foreground">
                Responses (dry run)
              </p>
              <ActionButtons alertId={a.id} actions={a.actions} onRequested={() => mutate()} />
              {a.action_requests.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
                  {a.action_requests.map((r) => (
                    <li key={r.id}>
                      {r.action.replace(/_/g, " ")} requested {formatTime(r.ts)} (dry run)
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </Section>

        <div className="flex flex-wrap gap-2 border-t pt-5">
          {a.status === "open" ? (
            <>
              <Button onClick={() => setStatus("resolved")}>
                <CheckCheck className="size-4" /> I&apos;ve dealt with this
              </Button>
              <Button variant="outline" onClick={() => setStatus("acknowledged")}>
                <Check className="size-4" /> Seen, will check later
              </Button>
            </>
          ) : (
            <Button variant="outline" onClick={() => setStatus("open")}>
              <RotateCcw className="size-4" /> Move back to Needs attention
            </Button>
          )}
        </div>
      </div>

      <div className="mt-6">
        <HowDecided a={a} />
      </div>
    </div>
  );
}

export default function AlertPage() {
  return (
    <Suspense fallback={<LoadingBlock rows={6} />}>
      <AlertView />
    </Suspense>
  );
}
