"use client";

import { Brain, Eye, Hand, Sparkles } from "lucide-react";

import type { Overview } from "@/lib/api";
import { cn } from "@/lib/utils";

/** The whole system in four steps, each with a live number. */
export function Pipeline({ data }: { data: Overview }) {
  const llama = data.explainer === "llama";
  const ex = data.explained ?? { total: 0, by_llama: 0, avg_latency_s: null, avg_decode_tps: null, avg_prefill_tps: null };
  const ml = data.ml;
  const steps = [
    {
      icon: Eye,
      title: "Watch",
      text: "Passive capture on Wi-Fi (Suricata)",
      metric: `${(data.flows_total ?? 0).toLocaleString()} connections from ${data.devices_total} devices`,
    },
    {
      icon: Brain,
      title: "Detect",
      text: ml ? "Rules, threat lists, ML classifier" : "Rules, threat lists",
      metric: ml
        ? `ML ${(ml.accuracy * 100).toFixed(1)}% accuracy (held-out)`
        : `${data.alerts_total} alerts so far`,
      ai: !!ml,
    },
    {
      icon: Sparkles,
      title: "Explain",
      text: llama ? "Llama 3.2 1B, on-device" : "Template summaries",
      metric: llama
        ? ex.by_llama
          ? `${ex.by_llama} explained · ~${ex.avg_latency_s?.toFixed(0)} s each`
          : "no alerts yet"
        : `${ex.total} explained`,
      ai: llama,
    },
    {
      icon: Hand,
      title: "You decide",
      text: "Next steps, dry-run responses",
      metric: "dry run",
    },
  ];
  return (
    <ol className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {steps.map((s, i) => (
        <li key={s.title} className="flex flex-col gap-2 rounded-xl border bg-card p-4">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "flex size-8 items-center justify-center rounded-lg",
                s.ai ? "bg-ai/12 text-ai" : "bg-primary/10 text-primary",
              )}
            >
              <s.icon className="size-4" />
            </span>
            <h3 className="font-semibold">
              <span className="text-muted-foreground">{i + 1}.</span> {s.title}
            </h3>
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground">{s.text}</p>
          <p className="mt-auto pt-1 text-xs font-medium tabular-nums">{s.metric}</p>
        </li>
      ))}
    </ol>
  );
}
