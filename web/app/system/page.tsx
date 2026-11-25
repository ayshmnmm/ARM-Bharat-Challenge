"use client";

import { Brain, CircleCheck, CircleMinus, CircleX, Cpu, MemoryStick, Router, Sparkles, Thermometer } from "lucide-react";

import { Empty, ErrorBlock, LoadingBlock, PageHeader, StatCard } from "@/components/common";
import { Pipeline } from "@/components/pipeline";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useApi, type FeedStatus, type MlInfo, type Overview, type SystemStatus } from "@/lib/api";
import { formatDuration } from "@/lib/format";

const SERVICE_LABEL: Record<string, string> = {
  dnsmasq: "Gives devices their addresses (dnsmasq)",
  hostapd: "Wi-Fi access point (hostapd)",
  "warp-svc": "Internet uplink (WARP)",
};

const FEATURE_PLAIN: Record<string, string> = {
  dst_port: "Which service was contacted",
  duration_s: "How long the connection lasted",
  fwd_pkts: "Packets sent",
  bwd_pkts: "Packets received back",
  fwd_payload: "Amount of data sent",
  bwd_payload: "Amount of data received",
  fwd_mean: "Data per packet sent",
  bwd_mean: "Data per packet received",
  bytes_per_s: "Data rate",
  pkts_per_s: "Packet rate",
  bwd_fwd_ratio: "Replies per packet sent",
};

const FAMILY: Record<string, string> = {
  benign: "Normal traffic",
  dos: "Flooding (denial of service)",
  scan: "Scanning",
  brute_force: "Password guessing",
  web_attack: "Web attacks",
  botnet: "Botnet",
};

const pct = (x: number, d = 1) => `${(x * 100).toFixed(d)}%`;

function MlCard({ ml }: { ml: MlInfo }) {
  const top = ml.importance.filter(([, v]) => v > 0).slice(0, 5);
  const maxImp = top[0]?.[1] || 1;
  const fp = ml.operating_point?.benign_flows_misflagged;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Brain className="size-5 text-ai" /> ML detector
        </CardTitle>
        <CardDescription className="leading-relaxed">
          Gradient-boosted trees, {ml.train_rows.toLocaleString()} labelled CIC-IDS2017 flows. Alerts at 10+ flows from one
          device at 90%+ confidence.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{pct(ml.accuracy)}</p>
            <p className="text-xs text-muted-foreground">accuracy, {ml.test_rows.toLocaleString()} held-out flows</p>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{fp != null ? pct(fp, 2) : "–"}</p>
            <p className="text-xs text-muted-foreground">false positive rate at 90% confidence</p>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{ml.inference_us_per_flow.toFixed(0)} µs</p>
            <p className="text-xs text-muted-foreground">per flow, Cortex-A72</p>
          </div>
        </div>

        {ml.lab_eval?.length ? (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Local captures (not in training set)</h3>
            <ul className="divide-y rounded-lg border text-sm">
              {ml.lab_eval.map((r) => {
                const ok = r.expected === "nothing" ? !r.ml_false_alarm : !!r.ml_detected_expected;
                const rulesCaught = !ok && r.expected !== "nothing" && r.rule_alerts.length > 0;
                return (
                  <li key={r.capture} className="flex items-start gap-3 p-3">
                    {ok ? (
                      <CircleCheck className="mt-0.5 size-5 shrink-0 text-ok" aria-label="As expected" />
                    ) : rulesCaught ? (
                      <CircleMinus className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-label="Caught by the rules" />
                    ) : (
                      <CircleX className="mt-0.5 size-5 shrink-0 text-sev-high" aria-label="Missed" />
                    )}
                    <div className="min-w-0 flex-1">
                      <p className="font-medium first-letter:uppercase">{r.contains}</p>
                      <p className="text-xs text-muted-foreground">
                        {r.expected === "nothing"
                          ? r.ml_false_alarm
                            ? "ML false positive"
                            : r.flows_flagged_by_ml
                              ? `No alert. ${r.flows_flagged_by_ml} / ${r.flows.toLocaleString()} flows scored, below alert threshold`
                              : `No alert, ${r.flows.toLocaleString()} flows`
                          : r.ml_detected_expected
                            ? `ML: ${FAMILY[r.expected]?.toLowerCase() ?? r.expected}`
                            : rulesCaught
                              ? "Rules only (synthetic packets, ML miss)"
                              : "Missed"}
                      </p>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}

        {ml.beyond_rules?.length ? (
          <div>
            <h3 className="mb-1 text-sm font-semibold">ML vs rules</h3>
            <p className="mb-2 text-xs text-muted-foreground">
              Low-rate probes spread across devices stay under rule thresholds; per-flow ML scores add up. Real nmap traffic.
            </p>
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="whitespace-normal pl-3">One source probes</TableHead>
                    <TableHead className="w-14 text-center">Rules</TableHead>
                    <TableHead className="w-14 pr-3 text-center">ML</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ml.beyond_rules.map((r) => (
                    <TableRow key={r.scenario} className={r.ml && !r.rules ? "bg-ai/10 hover:bg-ai/15" : undefined}>
                      <TableCell className="whitespace-normal pl-3">{r.scenario}</TableCell>
                      {[r.rules, r.ml].map((hit, i) => (
                        <TableCell key={i} className={i ? "pr-3" : undefined}>
                          {hit ? (
                            <CircleCheck className="mx-auto size-5 text-ok" aria-label="Caught" />
                          ) : (
                            <CircleX className="mx-auto size-5 text-muted-foreground" aria-label="Not caught" />
                          )}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Known limit: very slow probes (minutes apart).
            </p>
          </div>
        ) : null}

        {top.length > 0 && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Feature importance</h3>
            <ul className="space-y-2">
              {top.map(([f, v]) => (
                <li key={f} className="grid grid-cols-[minmax(0,12rem)_1fr] items-center gap-3 text-sm">
                  <span className="truncate">{FEATURE_PLAIN[f] ?? f}</span>
                  <span className="h-2 rounded-full bg-ai/70" style={{ width: `${Math.max(4, (v / maxImp) * 100)}%` }} />
                </li>
              ))}
            </ul>
          </div>
        )}

        <details className="rounded-lg border">
          <summary className="cursor-pointer p-3 text-sm font-medium">Per-class results</summary>
          <div className="overflow-x-auto border-t">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-3">Class</TableHead>
                  <TableHead className="text-right">Recall</TableHead>
                  <TableHead className="pr-3 text-right">Precision</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ml.classes.map((c) => (
                  <TableRow key={c}>
                    <TableCell className="pl-3">{FAMILY[c] ?? c}</TableCell>
                    <TableCell className="text-right tabular-nums">{pct(ml.per_class[c].recall)}</TableCell>
                    <TableCell className="pr-3 text-right tabular-nums">{pct(ml.per_class[c].precision)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}

function WriterCard({ ov }: { ov: Overview }) {
  const llama = ov.explainer === "llama";
  const ex = ov.explained;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="size-5 text-ai" /> LLM explainer
        </CardTitle>
        <CardDescription className="leading-relaxed">
          {llama ? "Llama 3.2 1B Instruct, ExecuTorch, Pi CPU. " : "Llama 3.2 1B (ExecuTorch): off, template summaries. "}
          Input: alert facts only. Output rejected on unknown numbers or addresses, or downplayed severity. Severity and
          actions come from the rules.
        </CardDescription>
      </CardHeader>
      {llama && ex.by_llama > 0 && (
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{ex.by_llama}</p>
            <p className="text-xs text-muted-foreground">alerts explained</p>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{ex.avg_latency_s?.toFixed(0)} s</p>
            <p className="text-xs text-muted-foreground">per explanation, incl. model load</p>
          </div>
          <div className="rounded-lg border p-3">
            <p className="text-2xl font-semibold tabular-nums">{ex.avg_decode_tps ?? "–"}</p>
            <p className="text-xs text-muted-foreground">decode tok/s, 2 of 4 cores</p>
          </div>
        </CardContent>
      )}
    </Card>
  );
}

export default function HowItWorksPage() {
  const { data: s, error } = useApi<SystemStatus>("/api/system", 5000);
  const { data: feeds } = useApi<FeedStatus>("/api/feeds", 60000);
  const { data: ov } = useApi<Overview>("/api/overview", 30000);

  if (error) return <ErrorBlock error={error} />;
  if (!s || !ov) return <LoadingBlock rows={6} />;

  const hot = s.temp_c !== null && s.temp_c >= 75;
  const routerOk = Object.values(s.router_services).every(Boolean);
  return (
    <div className="mx-auto max-w-4xl space-y-8">
      <PageHeader
        title="How NetWatch works"
        description="Detection, explanation and router health"
      />
      <Pipeline data={ov} />

      {ov.ml ? <MlCard ml={ov.ml} /> : null}
      <WriterCard ov={ov} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Router className="size-5 text-primary" /> Your router&apos;s health
          </CardTitle>
          <CardDescription>
            {routerOk ? "All router services up. " : "A router service is down. "}
            NetWatch: low priority, 2 of 4 cores, first to stop under memory pressure.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <StatCard label="CPU in use" value={`${s.cpu_percent.toFixed(0)}%`} icon={Cpu} />
            <StatCard
              label="Memory free"
              value={`${(s.mem_available_mb / 1024).toFixed(1)} GB`}
              hint={`NetWatch uses ${s.netwatch_rss_mb} MB`}
              icon={MemoryStick}
            />
            <StatCard
              label="Temperature"
              value={<span className={hot ? "text-sev-high" : undefined}>{s.temp_c !== null ? `${s.temp_c.toFixed(0)}°C` : "–"}</span>}
              hint={hot ? "Warm: heavy work is paused" : `up ${formatDuration(s.uptime_s)}`}
              icon={Thermometer}
            />
          </div>
          <ul className="space-y-2 text-sm">
            {Object.entries(s.router_services).map(([name, up]) => (
              <li key={name} className="flex items-center justify-between gap-3">
                <span>{SERVICE_LABEL[name] ?? name}</span>
                <Badge variant={up ? "secondary" : "destructive"}>{up ? "running" : "not running"}</Badge>
              </li>
            ))}
            <li className="flex items-center justify-between gap-3">
              <span>Traffic sensor (Suricata, Wi-Fi side only)</span>
              <Badge variant="secondary">
                {s.sensor_last_write_s === null ? "replaying recordings" : `active ${Math.round(s.sensor_last_write_s)} s ago`}
              </Badge>
            </li>
          </ul>
          <details className="rounded-lg border">
            <summary className="cursor-pointer p-3 text-sm font-medium">NetWatch processes</summary>
            <div className="border-t">
              {s.netwatch_processes.length === 0 ? (
                <Empty>No processes found</Empty>
              ) : (
                <Table>
                  <TableBody>
                    {s.netwatch_processes.map((p) => (
                      <TableRow key={p.pid}>
                        <TableCell className="pl-3">{p.name}</TableCell>
                        <TableCell className="pr-3 text-right tabular-nums">{p.rss_mb ?? "–"} MB</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </div>
          </details>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Threat lists</CardTitle>
          <CardDescription>
            Phishing, scam and malware lists, built offline and copied to the Pi.
            {feeds?.built_at && ` Last updated ${new Date(feeds.built_at).toLocaleDateString()}.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!feeds?.feeds.length ? (
            <Empty>No lists loaded</Empty>
          ) : (
            <ul className="divide-y text-sm">
              {feeds.feeds.map((f) => (
                <li key={`${f.name}-${f.kind}`} className="flex items-center justify-between gap-3 py-2">
                  <span>
                    {f.name} <span className="text-muted-foreground">· {f.category}</span>
                  </span>
                  <span className="tabular-nums text-muted-foreground">
                    {f.count.toLocaleString()} {f.kind === "ip" ? "addresses" : "sites"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
