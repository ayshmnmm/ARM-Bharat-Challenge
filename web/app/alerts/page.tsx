"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { AlertList } from "@/components/alert-list";
import { Empty, ErrorBlock, LoadingBlock, PageHeader } from "@/components/common";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useApi, type Alert, type Overview } from "@/lib/api";

const VIEWS = [
  { value: "open", label: "Needs attention" },
  { value: "acknowledged", label: "Seen" },
  { value: "resolved", label: "Dealt with" },
  { value: "all", label: "All" },
];

function AlertsView() {
  const params = useSearchParams();
  const router = useRouter();
  const view = params.get("status") ?? "open";
  const { data, error, isLoading } = useApi<Alert[]>(`/api/alerts${view === "all" ? "" : `?status=${view}`}`);
  const { data: ov } = useApi<Overview>("/api/overview", 30000);

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader title="Alerts" />
      <Tabs value={view} onValueChange={(v) => router.replace(`/alerts/?status=${v}`)} className="mb-4">
        <TabsList>
          {VIEWS.map((v) => (
            <TabsTrigger key={v.value} value={v.value}>
              {v.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      {error ? (
        <ErrorBlock error={error} />
      ) : isLoading && !data ? (
        <LoadingBlock rows={6} />
      ) : !data?.length ? (
        <Empty>{view === "open" ? "Nothing needs your attention." : "No alerts here."}</Empty>
      ) : (
        <AlertList alerts={data} now={ov?.clock} />
      )}
    </div>
  );
}

export default function AlertsPage() {
  return (
    <Suspense fallback={<LoadingBlock rows={6} />}>
      <AlertsView />
    </Suspense>
  );
}
