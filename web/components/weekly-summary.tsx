"use client";

import { CalendarDays, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import { post, useApi, type WeeklySummary } from "@/lib/api";
import { formatTime } from "@/lib/format";

/** "Your week": Llama's plain-English summary of the last 7 days, written on the Pi on request. */
export function WeeklySummaryCard() {
  const { data, mutate } = useApi<WeeklySummary>("/api/summary", 5000);
  const s = data?.summary;
  async function write() {
    await post("/api/summary", {});
    mutate();
  }
  return (
    <section className="rounded-xl border bg-card p-5">
      <div className="mb-2 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          <CalendarDays className="size-5 text-primary" /> Your week
        </h2>
        <Button variant="outline" size="sm" onClick={write} disabled={data?.writing}>
          {data?.writing ? "Writing…" : s ? "Update" : "Write summary"}
        </Button>
      </div>
      {data?.writing && (
        <p className="mb-2 flex items-center gap-1.5 text-sm text-ai">
          <Sparkles className="size-4 animate-pulse" /> Generating summary…
        </p>
      )}
      {s ? (
        <>
          <p className="leading-relaxed">{s.what}</p>
          <p className="mt-1 leading-relaxed text-muted-foreground">{s.why}</p>
          <p className="mt-2 text-xs text-muted-foreground">
            {s.provider.startsWith("llama")
              ? "Llama 3.2 1B · on-device"
              : "Template summary"} ·{" "}
            {formatTime(s.ts)}
          </p>
        </>
      ) : (
        !data?.writing && <p className="text-sm text-muted-foreground">Last 7 days</p>
      )}
    </section>
  );
}
