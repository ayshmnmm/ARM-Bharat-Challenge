"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import { Empty, ErrorBlock, LoadingBlock, Mono, PageHeader, SeverityDot } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi, type Device, type Overview } from "@/lib/api";
import { deviceName, formatBytes, formatTime, timeAgo } from "@/lib/format";

export default function DevicesPage() {
  const router = useRouter();
  const { data, error, isLoading } = useApi<Device[]>("/api/devices");
  const { data: ov } = useApi<Overview>("/api/overview");
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!data || !needle) return data ?? [];
    return data.filter((d) => [d.ip, d.hostname, d.kind, d.vendor, d.mac].some((v) => v?.toLowerCase().includes(needle)));
  }, [data, q]);

  return (
    <>
      <PageHeader title="Devices" />
      <Input placeholder="Search IP, name, type, vendor…" value={q} onChange={(e) => setQ(e.target.value)} className="mb-4 w-full sm:w-72" />
      {error ? (
        <ErrorBlock error={error} />
      ) : isLoading && !data ? (
        <LoadingBlock rows={6} />
      ) : (
        <Card className="py-0">
          <CardContent className="px-0">
            {rows.length === 0 ? (
              <Empty>No devices yet</Empty>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="pl-4">Device</TableHead>
                      <TableHead className="hidden md:table-cell">Type</TableHead>
                      <TableHead className="hidden lg:table-cell">MAC / vendor</TableHead>
                      <TableHead className="text-right">Traffic</TableHead>
                      <TableHead className="hidden text-right sm:table-cell">Last seen</TableHead>
                      <TableHead className="pr-4 text-right">Alerts</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((d) => (
                      <TableRow key={d.ip} className="cursor-pointer" onClick={() => router.push(`/device/?ip=${d.ip}`)}>
                        <TableCell className="pl-4">
                          <div className="flex items-center gap-2">
                            <span
                              className={d.active ? "size-2 rounded-full bg-ok" : "size-2 rounded-full bg-muted-foreground/40"}
                              title={d.active ? "Active" : "Idle"}
                            />
                            <span>
                              <span className="block font-medium">{deviceName(d, d.ip)}</span>
                              <Mono className="text-muted-foreground">{d.ip}</Mono>
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="hidden md:table-cell">
                          {d.kind || "Unknown"}
                          {d.mac_random ? <span className="block text-xs text-muted-foreground">private Wi-Fi address</span> : null}
                        </TableCell>
                        <TableCell className="hidden lg:table-cell">
                          <Mono>{d.mac ?? "–"}</Mono>
                          <span className="block text-xs text-muted-foreground">{d.vendor ?? ""}</span>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          ↓ {formatBytes(d.bytes_down)}
                          <span className="block text-muted-foreground">↑ {formatBytes(d.bytes_up)}</span>
                        </TableCell>
                        <TableCell className="hidden text-right text-sm text-muted-foreground sm:table-cell" title={formatTime(d.last_seen)}>
                          {timeAgo(d.last_seen, ov?.clock)}
                        </TableCell>
                        <TableCell className="pr-4 text-right">
                          {d.open_alerts ? (
                            <Badge variant="outline" className="gap-1.5">
                              <SeverityDot severity={d.worst_severity} />
                              {d.open_alerts}
                            </Badge>
                          ) : (
                            <span className="text-sm text-muted-foreground">–</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </>
  );
}
