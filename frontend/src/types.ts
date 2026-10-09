export interface Flow {
  id: Id;
  src_port: number;
  dst_port: number;
  src_ip: string;
  dst_ip: string;
  time: number;
  duration: number;
  // TODO: Get this from backend instead of hacky workaround
  service_tag: string;
  num_packets: number;
  parent_id: Id;
  child_id: Id;
  tags: string[];
  flags: string[];
  flagids: string[];
  suricata: number[];
  filename: string;
}

export interface TickInfo {
  startDate: string;
  tickLength: number;
  flagLifetime: number;
}

export interface FullFlow extends Flow {
  signatures: Signature[];
  flow: FlowRepresentation[];
}

export type Id = string;

export interface FlowRepresentation {
  type: string;
  flow: FlowData[];
}

export interface FlowData {
  from: string;
  data: string;
  b64: string;
  time: number;
}

export interface Signature {
  id: number;
  message: string;
  action: string;
}

// TODO: pagination WTF
export interface FlowsQuery {
  // Text filter
  regex_insensitive?: string;
  // Service filter
  // TODO: Why not use service name here?
  service?: string;
  ip_dst?: string;
  port_dst?: number;
  time_from?: string;
  time_to?: string;
  tags_include?: string[];
  tags_exclude?: string[];
  tag_intersection_mode?: "AND" | "OR";
  flags?: string[];
  flagids?: string[];
}

export interface StatsQuery {
  service: string;
  tick_from: number;
  tick_to: number;
}

export interface Stats {
  [key: string]: number; // little hack to make typescript happy
  tick: number;
  tag_flag_in: number;
  tag_flag_out: number;
  tag_blocked: number;
  tag_suricata: number;
  tag_enemy: number;
  flag_in: number;
  flag_out: number;
};

export type Service = {
  ip: string;
  port: number;
  name: string;
};

export type TicksAttackInfo = Record<number, Record<string, number>>;

export interface TicksAttackQuery {
  from_tick: number;
  to_tick: number;
}

export type TriageClassification = "attack" | "checker" | "unknown";

export interface FiregexRule {
  pattern: string;
  mode: "S" | "C" | "B";
  case_sensitive: boolean;
  engine: string;
  specificity: "high" | "medium";
  warning: string;
}

export interface TriageGroup {
  fingerprint: string;
  classification: TriageClassification;
  confidence: number;
  reasons: string[];
  count: number;
  first_seen: string;
  last_seen: string;
  representative_flow_id: string;
  service: string;
  ip_dst: string;
  port_dst: number;
  method: string | null;
  path: string | null;
  status: number | null;
  request_preview: string;
  response_preview: string;
  request_bytes: number;
  response_bytes: number;
  source: "live sample · redacted" | "synthetic demo";
  firegex: FiregexRule | null;
}

export interface IngestionHealth {
  status: "healthy" | "stale" | "empty";
  last_flow_time: string | null;
  age_seconds: number | null;
  flows_last_minute: number;
  current_tick: number;
  captured_tick: number | null;
  capture_delay_ticks: number | null;
}

export interface AttackFarmExport {
  filename: string;
  protocol: "http" | "tcp";
  port: number;
  service: string;
  runtime: string;
  code: string;
  candidates: { value: string; kind: string; recommended_attack_info: boolean }[];
  variables: { name: string; purpose: string }[];
  context_fields: { name: string; purpose: string }[];
}
