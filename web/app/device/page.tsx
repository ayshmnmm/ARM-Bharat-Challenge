"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Suspense } from "react";

import { AlertList } from "@/components/alert-list";
import { Empty, ErrorBlock, LoadingBlock, Mono, PageHeader, StatCard } from "@/components/common";
import { TrafficChart } from "@/components/traffic-chart";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useApi, type DeviceDetail } from "@/lib/api";
import { deviceName, formatBytes, formatTime } from "@/lib/format";

function DeviceView() {
  const ip = useSearchParams().get("ip");
  const { data, error, isLoading } = useApi<DeviceDetail>(ip ? `/api/devices/${ip}` : null);

  if (!ip) return <Empty>No device selected</Empty>;
  if (error) return <ErrorBlock error={error} />;
  if (isLoading || !data) return <LoadingBlock rows={6} />;
  const d = data.device;

  return (
    <>
      <Button asChild variant="ghost" size="sm" className="-ml-2 mb-2">
        <Link href="/devices/">
          <ArrowLeft className="size-4" /> Devices
        </Link>
      </Button>
      <PageHeader
        title={deviceName(d, d.ip)}
        description={
          <span className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">{d.kind || "Unknown"}</Badge>
            <Mono>{d.ip}</Mono>
            {d.mac && <Mono>· {d.mac}</Mono>}
            {d.vendor && <span>· {d.vendor}</span>}
          </span>
        }
      />

      <section className="mb-8">
        <h2 className="mb-3 text-lg font-semibold">
          {data.alerts.length ? `Alerts (${data.alerts.length})` : "No alerts"}
        </h2>
        {data.alerts.length > 0 && <AlertList alerts={data.alerts} showSummary={false} />}
      </section>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Downloaded" value={formatBytes(d.bytes_down)} />
        <StatCard label="Uploaded" value={formatBytes(d.bytes_up)} />
        <StatCard label="Connections" value={d.flows.toLocaleString()} />
        <StatCard label="First seen" value={<span className="text-base">{formatTime(d.first_seen)}</span>} hint={`last ${formatTime(d.last_seen)}`} />
      </div>

      <div>
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>Traffic</CardTitle>
            <CardDescription>Per minute, last active hour</CardDescription>
          </CardHeader>
          <CardContent>
            <TrafficChart data={data.traffic} end={d.last_seen} height={200} />
          </CardContent>
        </Card>
      </div>

      <details className="group mt-6 rounded-xl border bg-card">
        <summary className="cursor-pointer list-none p-5">
          <span className="font-semibold">Connections</span>
        </summary>
        <div className="border-t p-5">
          <Tabs defaultValue="sites">
            <TabsList className="mb-4 h-auto flex-wrap">
              <TabsTrigger value="destinations">Addresses</TabsTrigger>
              <TabsTrigger value="sites">Websites</TabsTrigger>
              <TabsTrigger value="dns">DNS lookups</TabsTrigger>
              <TabsTrigger value="fingerprints">Fingerprints</TabsTrigger>
            </TabsList>

            <TabsContent value="destinations" className="overflow-x-auto">
              {data.destinations.length === 0 ? (
                <Empty>No connections recorded</Empty>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Destination</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead className="text-right">Connections</TableHead>
                      <TableHead className="text-right">Down / Up</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.destinations.map((x) => (
                      <TableRow key={`${x.dst_ip}-${x.dst_port}-${x.proto}`}>
                        <TableCell>
                          <span className="block max-w-xs truncate">{x.name ?? <Mono>{x.dst_ip}</Mono>}</span>
                          {x.name && <Mono className="text-muted-foreground">{x.dst_ip}</Mono>}
                        </TableCell>
                        <TableCell>
                          <Mono>
                            {x.proto}/{x.dst_port ?? "–"}
                          </Mono>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">{x.flows}</TableCell>
                        <TableCell className="text-right font-mono text-xs tabular-nums">
                          {formatBytes(x.down)} / {formatBytes(x.up)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="sites" className="overflow-x-auto">
              {data.tls.length === 0 ? (
                <Empty>No HTTPS sites recorded</Empty>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Site name (SNI)</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead className="text-right">Times</TableHead>
                      <TableHead className="hidden text-right md:table-cell">Last</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.tls.map((t) => (
                      <TableRow key={`${t.sni}-${t.transport}`}>
                        <TableCell className="max-w-xs truncate">{t.sni}</TableCell>
                        <TableCell>{t.transport === "quic" ? "HTTP/3 (QUIC)" : "TLS"}</TableCell>
                        <TableCell className="text-right tabular-nums">{t.n}</TableCell>
                        <TableCell className="hidden text-right text-muted-foreground md:table-cell">{formatTime(t.last)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="dns" className="overflow-x-auto">
              {data.dns.length === 0 ? (
                <Empty>No DNS lookups recorded</Empty>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Result</TableHead>
                      <TableHead className="hidden text-right md:table-cell">Time</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.dns.map((q, i) => (
                      <TableRow key={i}>
                        <TableCell className="max-w-xs truncate">{q.rrname}</TableCell>
                        <TableCell>
                          <Mono>{q.rrtype}</Mono>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{q.rcode ?? "no answer"}</TableCell>
                        <TableCell className="hidden text-right text-muted-foreground md:table-cell">{formatTime(q.ts)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>

            <TabsContent value="fingerprints">
              {data.fingerprints.length === 0 ? (
                <Empty>No TLS fingerprints recorded</Empty>
              ) : (
                <ul className="space-y-2">
                  {data.fingerprints.map((f) => (
                    <li key={f.ja4} className="flex items-center justify-between gap-3 text-sm">
                      <Mono className="truncate">{f.ja4}</Mono>
                      <span className="tabular-nums text-muted-foreground">{f.n} connections</span>
                    </li>
                  ))}
                </ul>
              )}
            </TabsContent>
          </Tabs>
        </div>
      </details>
    </>
  );
}

export default function DevicePage() {
  return (
    <Suspense fallback={<LoadingBlock rows={6} />}>
      <DeviceView />
    </Suspense>
  );
}
