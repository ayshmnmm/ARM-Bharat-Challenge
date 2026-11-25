"use client";

import { Badge } from "@/components/ui/badge";
import { humanize, unitFor } from "@/lib/format";

const MAX_ITEMS = 12;

function Value({ value, unit = "" }: { value: unknown; unit?: string }) {
  if (value === null || value === undefined || value === "") return <span className="text-muted-foreground">–</span>;
  if (typeof value === "boolean") return <span>{value ? "Yes" : "No"}</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-muted-foreground">none</span>;
    if (value.every((v) => typeof v !== "object")) {
      return (
        <div className="flex flex-wrap gap-1">
          {value.slice(0, MAX_ITEMS).map((v, i) => (
            <Badge key={i} variant="secondary" className="font-mono font-normal">
              {String(v)}
            </Badge>
          ))}
          {value.length > MAX_ITEMS && <span className="text-xs text-muted-foreground">+{value.length - MAX_ITEMS} more</span>}
        </div>
      );
    }
    return (
      <ul className="space-y-1">
        {value.map((v, i) => (
          <li key={i} className="font-mono text-xs">
            {Object.entries(v as Record<string, unknown>)
              .filter(([k, x]) => x !== null && k !== "fetched_at")
              .map(([k, x]) => `${k}: ${x}`)
              .join(" · ")}
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") return <pre className="text-xs">{JSON.stringify(value, null, 2)}</pre>;
  return (
    <span className="font-mono">
      {typeof value === "number" ? value.toLocaleString() : String(value)}
      {unit && <span className="text-muted-foreground">{unit}</span>}
    </span>
  );
}

/** Renders a detector's evidence object as a readable key/value list. */
export function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  const entries = Object.entries(evidence).filter(([k, v]) => k !== "notes" && !(Array.isArray(v) && v.length === 0 && k.endsWith("_ips")));
  const notes = (evidence.notes as string[] | undefined) ?? [];
  return (
    <div className="space-y-4">
      {notes.length > 0 && (
        <ul className="space-y-1 rounded-md bg-muted p-3 text-sm">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[max-content_1fr]">
        {entries.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{humanize(k)}</dt>
            <dd className="min-w-0 break-words">
              <Value value={v} unit={unitFor(k)} />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
