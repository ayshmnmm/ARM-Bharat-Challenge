"use client";

import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";

import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { TrafficPoint } from "@/lib/api";
import { formatBytes, formatClock } from "@/lib/format";

/** Short axis labels ("68 KB") so they never wrap on a phone. */
const tick = (v: number) => formatBytes(v).replace(/\.\d+ /, " ");

const config = {
  down: { label: "Download", color: "var(--chart-1)" },
  up: { label: "Upload", color: "var(--chart-2)" },
} satisfies ChartConfig;

/** One bar per minute for the hour ending at `end`; quiet minutes are shown as zero, not skipped. */
function fillMinutes(data: TrafficPoint[], end?: number): TrafficPoint[] {
  const last = Math.floor((end ?? data[data.length - 1]?.t ?? 0) / 60) * 60;
  if (!last) return data;
  const byMinute = new Map(data.map((p) => [p.t, p]));
  return Array.from({ length: 60 }, (_, i) => {
    const t = last - (59 - i) * 60;
    return byMinute.get(t) ?? { t, up: 0, down: 0 };
  });
}

export function TrafficChart({ data, end, height = 220 }: { data: TrafficPoint[]; end?: number; height?: number }) {
  if (!data.length) {
    return (
      <div className="flex items-center justify-center text-sm text-muted-foreground" style={{ height }}>
        No traffic in this hour
      </div>
    );
  }
  return (
    <ChartContainer config={config} className="w-full" style={{ height }}>
      <BarChart data={fillMinutes(data, end)} margin={{ left: 0, right: 4, top: 8 }} barCategoryGap={1}>
        <CartesianGrid vertical={false} />
        <XAxis dataKey="t" tickFormatter={formatClock} tickLine={false} axisLine={false} minTickGap={48} />
        <YAxis tickFormatter={tick} tickLine={false} axisLine={false} width={56} />
        <ChartTooltip
          cursor={{ fill: "var(--muted)" }}
          content={
            <ChartTooltipContent
              labelFormatter={(_, p) => formatClock(p?.[0]?.payload?.t)}
              formatter={(value, name) => (
                <div className="flex w-full justify-between gap-4">
                  <span className="text-muted-foreground">{config[name as keyof typeof config]?.label ?? name}</span>
                  <span className="font-mono tabular-nums">{formatBytes(Number(value))}</span>
                </div>
              )}
            />
          }
        />
        <Bar dataKey="down" stackId="t" fill="var(--color-down)" radius={[0, 0, 0, 0]} />
        <Bar dataKey="up" stackId="t" fill="var(--color-up)" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ChartContainer>
  );
}
