"use client";

import useSWR, { type SWRConfiguration } from "swr";

export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "open" | "acknowledged" | "resolved";

export interface DeviceRef {
  hostname: string | null;
  kind: string | null;
  vendor: string | null;
}

export interface Alert {
  id: number;
  detector: string;
  kind: string;
  severity: Severity;
  title: string;
  device_ip: string | null;
  peer: string | null;
  ts_first: number;
  ts_last: number;
  ts_raised?: number | null;
  count: number;
  status: AlertStatus;
  evidence: Record<string, unknown>;
  device?: DeviceRef | null;
  explained?: boolean;
  /** Jargon-free one-liner: who did what. */
  headline?: string;
  /** Plain-English summary: the AI's text once written, the rule-based text until then. */
  summary?: string;
}

export interface Explanation {
  provider: string;
  model: string | null;
  summary: string;
  why: string;
  risk: string;
  actions: string[];
  latency_ms: number;
  created?: number;
  /** The grounded facts the explanation was written from. */
  facts: string[];
  /** True while the on-device model is still writing; the text shown is the rule-based version. */
  pending: boolean;
  stats: {
    prefill_token_per_sec?: number;
    decode_token_per_sec?: number;
    prompt_tokens?: number;
    generated_tokens?: number;
  } | null;
}

export interface ActionOption {
  action: string;
  label: string;
  target: string;
  command_preview: string;
}

export interface ActionRequest {
  id: number;
  ts: number;
  action: string;
  target: string;
  command_preview: string;
  status: string;
}

/** One rule the detector checked: shown as "Why NetWatch flagged this". */
export interface Criterion {
  check: string;
  observed: string;
  rule: string;
  met: boolean;
}

export interface AlertDetail extends Alert {
  explanation: Explanation;
  criteria: Criterion[];
  actions: ActionOption[];
  action_requests: ActionRequest[];
}

export interface Device {
  ip: string;
  mac: string | null;
  mac_random: number;
  vendor: string | null;
  hostname: string | null;
  kind: string | null;
  first_seen: number;
  last_seen: number;
  bytes_up: number;
  bytes_down: number;
  flows: number;
  trusted: number;
  active?: boolean;
  open_alerts?: number;
  worst_severity?: Severity | null;
}

export interface TrafficPoint {
  t: number;
  up: number;
  down: number;
  flows?: number;
}

export interface Overview {
  clock: number;
  devices_total: number;
  devices_active: number;
  alerts_open: Record<Severity, number>;
  alerts_total: number;
  traffic: TrafficPoint[];
  top_talkers: Pick<Device, "ip" | "hostname" | "kind" | "bytes_up" | "bytes_down">[];
  recent_alerts: Alert[];
  feeds: { built_at: string | null; domains: number; ips: number };
  explainer: string;
  explainer_model: string | null;
  flows_total: number;
  dns_total: number;
  explained: {
    total: number;
    by_llama: number;
    avg_latency_s: number | null;
    avg_decode_tps: number | null;
    avg_prefill_tps: number | null;
  };
  ml?: MlInfo | null;
  ml_alerts?: number;
  ml_confirmed?: number;
}

export interface MlInfo {
  algorithm: string;
  dataset: string;
  classes: string[];
  accuracy: number;
  macro_f1: number;
  per_class: Record<string, { precision: number; recall: number; "f1-score": number; support?: number }>;
  train_rows: number;
  test_rows: number;
  inference_us_per_flow: number;
  features: string[];
  importance: [string, number][];
  operating_point?: { min_confidence: number; benign_flows_misflagged: number; macro_f1: number } | null;
  lab_eval?: {
    capture: string;
    contains: string;
    expected: string;
    flows: number;
    flows_flagged_by_ml: number;
    flagged_share: number;
    rule_alerts: string[];
    ml_alerts: string[];
    ml_detected_expected: boolean | null;
    ml_false_alarm: boolean | null;
  }[] | null;
  beyond_rules?: { scenario: string; cases: number; rules: boolean; ml: boolean }[] | null;
}

export interface DeviceDetail {
  device: Device;
  traffic: TrafficPoint[];
  destinations: {
    dst_ip: string;
    dst_port: number;
    proto: string;
    flows: number;
    up: number;
    down: number;
    last: number;
    name: string | null;
  }[];
  dns: { ts: number; rrname: string; rrtype: string; rcode: string | null }[];
  tls: { sni: string; transport: string; last: number; n: number; ja4: string | null }[];
  fingerprints: { ja4: string; n: number }[];
  alerts: Alert[];
}

export interface TimelineEvent {
  ts: number;
  type: "alert" | "device" | "action";
  severity: Severity | null;
  title: string;
  device_ip: string | null;
  alert_id: number | null;
}

export interface SystemStatus {
  time: number;
  uptime_s: number;
  cpu_percent: number;
  load: [number, number, number];
  mem_total_mb: number;
  mem_available_mb: number;
  mem_percent: number;
  temp_c: number | null;
  throttled: string | null;
  netwatch_processes: { pid: number; name: string; rss_mb: number | null }[];
  netwatch_rss_mb: number;
  router_services: Record<string, boolean>;
  db_size_mb: number;
  sensor_last_write_s: number | null;
}

export interface FeedStatus {
  built_at: string | null;
  domains: number;
  ips: number;
  feeds: { name: string; kind: string; category: string; count: number; source: string; fetched_at: string | null }[];
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (res.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/login") && !window.location.pathname.startsWith("/login")) {
    window.location.href = "/login/";
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const fetcher = <T,>(path: string) => request<T>(path);

export function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

/** Polls every few seconds so the dashboard follows live traffic. */
export function useApi<T>(path: string | null, refreshMs = 5000, opts?: SWRConfiguration<T>) {
  return useSWR<T>(path, fetcher, { refreshInterval: refreshMs, keepPreviousData: true, ...opts });
}


export interface WeeklySummary {
  summary: { ts: number; days: number; what: string; why: string; provider: string; latency_ms: number; facts: string[] } | null;
  writing: boolean;
}
