"use client";

import { AlertTriangle, Inbox } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import type { AlertStatus, Severity } from "@/lib/api";
import { SEVERITY_WORD } from "@/lib/format";
import { cn } from "@/lib/utils";

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-sev-critical text-white border-transparent",
  high: "bg-sev-high text-white border-transparent",
  medium: "bg-sev-medium text-black border-transparent",
  low: "bg-sev-low/15 text-sev-low border-sev-low/30",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge className={cn(SEV_STYLE[severity], className)} title={`Severity: ${severity}`}>
      {SEVERITY_WORD[severity]}
    </Badge>
  );
}

export function SeverityDot({ severity }: { severity: Severity | null | undefined }) {
  if (!severity) return <span className="inline-block size-2 rounded-full bg-ok" />;
  const tone = { critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low" }[severity];
  return <span className={cn("inline-block size-2 rounded-full", tone)} />;
}

export function StatusBadge({ status }: { status: AlertStatus }) {
  return (
    <Badge variant={status === "open" ? "outline" : "secondary"}>
      {{ open: "New", acknowledged: "Seen", resolved: "Dealt with" }[status]}
    </Badge>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon: Icon,
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="flex flex-row items-center justify-between px-4">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
        {Icon && <Icon className="size-4 text-muted-foreground" />}
      </CardHeader>
      <CardContent className="px-4">
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
      </CardContent>
    </Card>
  );
}

export function LoadingBlock({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

export function ErrorBlock({ error }: { error: unknown }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm">
      <AlertTriangle className="size-4 text-destructive" />
      <span>Could not load data: {error instanceof Error ? error.message : String(error)}</span>
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-10 text-center text-sm text-muted-foreground">
      <Inbox className="size-6" />
      {children}
    </div>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[0.85em]", className)}>{children}</span>;
}
