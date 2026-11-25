"use client";

import Link from "next/link";
import { Bell, Monitor, MousePointerClick } from "lucide-react";

import { Empty, ErrorBlock, LoadingBlock, PageHeader, SeverityBadge } from "@/components/common";
import { Card, CardContent } from "@/components/ui/card";
import { useApi, type TimelineEvent } from "@/lib/api";
import { formatTime } from "@/lib/format";

const ICON = { alert: Bell, device: Monitor, action: MousePointerClick };

function dayKey(ts: number) {
  return new Date(ts * 1000).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "long" });
}

export default function TimelinePage() {
  const { data, error, isLoading } = useApi<TimelineEvent[]>("/api/timeline");

  const days = new Map<string, TimelineEvent[]>();
  for (const e of data ?? []) {
    const k = dayKey(e.ts);
    days.set(k, [...(days.get(k) ?? []), e]);
  }

  return (
    <>
      <PageHeader title="Timeline" />
      {error ? (
        <ErrorBlock error={error} />
      ) : isLoading && !data ? (
        <LoadingBlock rows={8} />
      ) : !data?.length ? (
        <Empty>Nothing has happened yet</Empty>
      ) : (
        <div className="space-y-6">
          {[...days.entries()].map(([day, events]) => (
            <section key={day}>
              <h2 className="mb-2 text-sm font-medium text-muted-foreground">{day}</h2>
              <Card className="py-2">
                <CardContent className="px-0">
                  <ol className="divide-y">
                    {events.map((e, i) => {
                      const Icon = ICON[e.type];
                      const body = (
                        <div className="flex items-start gap-3 px-4 py-3">
                          <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                          <div className="min-w-0 flex-1">
                            <p className="text-sm">{e.title}</p>
                            <p className="text-xs text-muted-foreground">{formatTime(e.ts)}</p>
                          </div>
                          {e.severity && <SeverityBadge severity={e.severity} />}
                        </div>
                      );
                      const href = e.alert_id ? `/alert/?id=${e.alert_id}` : e.device_ip ? `/device/?ip=${e.device_ip}` : null;
                      return (
                        <li key={`${e.type}-${e.ts}-${i}`}>
                          {href ? (
                            <Link href={href} className="block hover:bg-accent/40">
                              {body}
                            </Link>
                          ) : (
                            body
                          )}
                        </li>
                      );
                    })}
                  </ol>
                </CardContent>
              </Card>
            </section>
          ))}
        </div>
      )}
    </>
  );
}
