// Human-readable names for the MITRE ATT&CK tags this app's rules.yaml
// produces. No mapping like this exists in the backend — these are display
// labels only, kept here so ThreatTypeChart and ChainList stay consistent.
interface TechniqueMeta {
  chainTitle: string;
}

const MITRE_TECHNIQUES: Record<string, TechniqueMeta> = {
  T1110: { chainTitle: "Brute Force Attack" },
  T1133: { chainTitle: "External Remote Services Attack" },
  T1189: { chainTitle: "Drive-by Compromise" },
  T1041: { chainTitle: "Data Exfiltration" },
};

export function mitreChainTitle(tag: string | null): string {
  if (!tag) return "Correlated Anomalies";
  return MITRE_TECHNIQUES[tag]?.chainTitle ?? tag;
}

// Keyed by rule_name rather than mitre_tag: repeated_failed_login_attempts
// (low severity) intentionally shares T1110 with high_request_volume (it's
// the same technique at an unconfirmed-attempt stage), so a tag-only lookup
// would merge their bars in ThreatTypeChart. Rule name is always 1:1 with a
// distinct severity/name, so grouping by it keeps them as separate bars.
const RULE_TECHNIQUE_NAME: Record<string, string> = {
  high_request_volume: "Brute Force",
  off_hours_risky_access: "External Remote Svcs",
  threat_detected: "Drive-by Compromise",
  large_data_transfer: "Exfiltration Over C2",
  repeated_failed_login_attempts: "Brute Force (Unsuccessful)",
};

export function ruleTechniqueName(ruleName: string): string {
  return RULE_TECHNIQUE_NAME[ruleName] ?? ruleName.replace(/_/g, " ");
}
