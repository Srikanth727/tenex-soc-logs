"use client";

import { useMemo, useState } from "react";
import { SEVERITY_BG_CLASS, isKnownSeverity } from "@/lib/severityColors";
import { ruleTechniqueName } from "@/lib/mitre";

interface AnomalyLite {
  rule_name: string;
  mitre_tag: string | null;
  severity: string | null;
}

interface ThreatTypeChartProps {
  anomalies: AnomalyLite[];
}

interface Bucket {
  ruleName: string;
  tag: string | null;
  count: number;
  severity: string | null;
}

const TOP_N = 5;
const BAR_HEIGHT = 28;
const BAR_GAP = 14;

function ChartCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="w-full min-w-0 overflow-hidden rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Top threat types (MITRE ATT&amp;CK)</h2>
      <div className="mt-3 min-w-0">{children}</div>
    </div>
  );
}

export default function ThreatTypeChart({ anomalies }: ThreatTypeChartProps) {
  const [hovered, setHovered] = useState<string | null>(null);

  const buckets = useMemo(() => {
    // Grouped by rule_name, not mitre_tag: repeated_failed_login_attempts
    // (low) intentionally shares T1110 with high_request_volume (high), and
    // a tag-only grouping would merge their counts/colors into one bar.
    // Severity is fixed per rule (see rules.yaml), so the first anomaly seen
    // for a rule already tells us that rule's severity.
    const byRule = new Map<string, Bucket>();
    for (const a of anomalies) {
      const existing = byRule.get(a.rule_name);
      if (existing) {
        existing.count += 1;
      } else {
        byRule.set(a.rule_name, { ruleName: a.rule_name, tag: a.mitre_tag, count: 1, severity: a.severity });
      }
    }
    return Array.from(byRule.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, TOP_N);
  }, [anomalies]);

  const total = anomalies.length;
  const maxCount = Math.max(1, ...buckets.map((b) => b.count));

  if (buckets.length === 0) {
    return (
      <ChartCard>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">No threats detected yet.</p>
      </ChartCard>
    );
  }

  return (
    <ChartCard>
      <div className="flex flex-col" style={{ gap: BAR_GAP }}>
        {buckets.map((b) => {
          const severityClass = isKnownSeverity(b.severity) ? SEVERITY_BG_CLASS[b.severity] : "bg-zinc-400";
          return (
            <div
              key={b.ruleName}
              className="group relative flex min-w-0 items-center gap-3"
              style={{ height: BAR_HEIGHT }}
              onMouseEnter={() => setHovered(b.ruleName)}
              onMouseLeave={() => setHovered(null)}
            >
              {/* Fixed width, not a viewport (`sm:`) breakpoint switch — this
                  card is always full-width in the dashboard, but a viewport
                  breakpoint doesn't track the *column's* actual width (same
                  class of bug the SeverityChart legend had), so a single
                  fixed value is the correct choice here. w-48 (not w-32) so
                  the longest label — "T1110 Brute Force (Unsuccessful)" —
                  fits without truncating; the title attribute is a fallback
                  for anything that still doesn't fit at narrower widths. */}
              <div
                className="w-48 shrink-0 truncate text-xs font-medium text-zinc-600 dark:text-zinc-300"
                title={`${b.tag ?? ""} ${ruleTechniqueName(b.ruleName)}`.trim()}
              >
                <span className="text-zinc-400 dark:text-zinc-500">{b.tag}</span> {ruleTechniqueName(b.ruleName)}
              </div>
              <div className="relative min-w-0 flex-1 rounded bg-zinc-100 dark:bg-zinc-900" style={{ height: BAR_HEIGHT }}>
                <div
                  className={`h-full rounded transition-opacity ${severityClass}`}
                  style={{ width: `${(b.count / maxCount) * 100}%`, opacity: hovered === null || hovered === b.ruleName ? 1 : 0.5 }}
                  tabIndex={0}
                  onFocus={() => setHovered(b.ruleName)}
                  onBlur={() => setHovered(null)}
                />
                {hovered === b.ruleName && (
                  <div className="absolute bottom-full left-0 z-10 mb-1.5 whitespace-nowrap rounded-md bg-zinc-900 px-2 py-1 text-xs text-white shadow-lg dark:bg-zinc-100 dark:text-zinc-900">
                    {b.count} events ({total > 0 ? Math.round((b.count / total) * 100) : 0}% of total)
                  </div>
                )}
              </div>
              <div className="w-8 shrink-0 text-right text-xs font-semibold tabular-nums text-zinc-700 dark:text-zinc-300">
                {b.count}
              </div>
            </div>
          );
        })}
      </div>
    </ChartCard>
  );
}
