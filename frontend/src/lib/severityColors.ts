// Fixed hue order (never cycled/reordered) so severity always maps to the
// same color across SeverityChart, ThreatTypeChart, ChainList, FilterBar,
// and AnomalyTable. This is the single source of truth — no component
// should hardcode a severity hex/named-color of its own.
export const SEVERITY_ORDER = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

// Hex reference (light mode). Medium and Low both needed adjustment from the
// originally requested #eab308 / #22c55e — both FAILed the dataviz palette
// validator's lightness band and/or CVD-separation-from-orange checks in at
// least one mode (bright yellow/green are inherently high-lightness, which
// clashes with a light surface). See severityColors.test notes in the PR
// description for the validator output; these are the nearest passing shades:
//   - medium: light #d4a017 / dark #b45309 (mirrors the critical/high split)
//   - low: #16a34a passes both modes unchanged
export const SEVERITY_HEX: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d4a017",
  low: "#16a34a",
};

export const SEVERITY_BG_CLASS: Record<Severity, string> = {
  critical: "bg-[#dc2626]",
  high: "bg-[#ea580c]",
  medium: "bg-[#d4a017] dark:bg-[#b45309]",
  low: "bg-[#16a34a]",
};

export const SEVERITY_FILL_CLASS: Record<Severity, string> = {
  critical: "fill-[#dc2626]",
  high: "fill-[#ea580c]",
  medium: "fill-[#d4a017] dark:fill-[#b45309]",
  low: "fill-[#16a34a]",
};

export const SEVERITY_STROKE_CLASS: Record<Severity, string> = {
  critical: "stroke-[#dc2626]",
  high: "stroke-[#ea580c]",
  medium: "stroke-[#d4a017] dark:stroke-[#b45309]",
  low: "stroke-[#16a34a]",
};

// Text-color variant for badges/pills that need severity-colored text rather
// than a filled background (e.g. AnomalyTable's severity column, FilterBar's
// "off" state doesn't use this, but the "on" pills do via bg + a fixed
// light-on-dark text pairing — see each component for which variant it uses).
export const SEVERITY_TEXT_CLASS: Record<Severity, string> = {
  critical: "text-[#dc2626]",
  high: "text-[#ea580c]",
  medium: "text-[#a16207] dark:text-[#d4a017]",
  low: "text-[#15803d] dark:text-[#16a34a]",
};

// Pastel badge (bg tint + readable text) used by AnomalyTable's severity pill.
export const SEVERITY_BADGE_CLASS: Record<Severity, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
  low: "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
};

export function isKnownSeverity(severity: string | null | undefined): severity is Severity {
  return severity != null && (SEVERITY_ORDER as readonly string[]).includes(severity);
}
