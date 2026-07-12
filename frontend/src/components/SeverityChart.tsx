"use client";

import { useMemo, useState } from "react";
import {
  SEVERITY_ORDER,
  SEVERITY_LABEL,
  SEVERITY_BG_CLASS,
  SEVERITY_STROKE_CLASS,
  Severity,
  isKnownSeverity,
} from "@/lib/severityColors";

interface AnomalyLite {
  severity: string | null;
}

interface SeverityChartProps {
  anomalies: AnomalyLite[];
}

const SIZE = 200;
const STROKE_WIDTH = 28;
const RADIUS = (SIZE - STROKE_WIDTH) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const CENTER = SIZE / 2;

function ChartCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="h-full w-full min-w-0 overflow-hidden rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Anomaly severity distribution</h2>
      <div className="mt-3 min-w-0">{children}</div>
    </div>
  );
}

export default function SeverityChart({ anomalies }: SeverityChartProps) {
  const [hovered, setHovered] = useState<Severity | null>(null);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of anomalies) {
      if (isKnownSeverity(a.severity)) c[a.severity] += 1;
    }
    return c;
  }, [anomalies]);

  const total = counts.critical + counts.high + counts.medium + counts.low;

  if (total === 0) {
    return (
      <ChartCard>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">No anomalies to summarize yet.</p>
      </ChartCard>
    );
  }

  const lengths = SEVERITY_ORDER.map((sev) => (counts[sev] / total) * CIRCUMFERENCE);
  const segments = SEVERITY_ORDER.map((sev, i) => ({
    sev,
    value: counts[sev],
    fraction: counts[sev] / total,
    length: lengths[i],
    // Pure prefix sum (fresh reduce per segment, no mutated accumulator) —
    // cheap since there are only 3 severities.
    offset: lengths.slice(0, i).reduce((a, b) => a + b, 0),
  }));

  const hoveredSeg = hovered ? segments.find((s) => s.sev === hovered) : null;

  return (
    <ChartCard>
      {/* Always stacked (never side-by-side): this card lives in a ~1/3-width
          grid column, and `sm:` is a viewport breakpoint, not a column-width
          one — it would force a cramped row here regardless of how narrow
          the actual column is at typical desktop viewport widths. */}
      <div className="flex min-w-0 flex-col items-center gap-4">
        <div className="relative shrink-0" style={{ width: SIZE, height: SIZE }}>
          <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`}>
            <circle
              cx={CENTER}
              cy={CENTER}
              r={RADIUS}
              fill="none"
              strokeWidth={STROKE_WIDTH}
              className="stroke-zinc-100 dark:stroke-zinc-900"
            />
            <g transform={`rotate(-90 ${CENTER} ${CENTER})`}>
              {segments
                .filter((s) => s.value > 0)
                .map((s) => (
                  <circle
                    key={s.sev}
                    cx={CENTER}
                    cy={CENTER}
                    r={RADIUS}
                    fill="none"
                    strokeWidth={STROKE_WIDTH}
                    strokeDasharray={`${s.length} ${CIRCUMFERENCE - s.length}`}
                    strokeDashoffset={-s.offset}
                    className={`${SEVERITY_STROKE_CLASS[s.sev]} transition-opacity`}
                    style={{ opacity: hovered === null || hovered === s.sev ? 1 : 0.35 }}
                    tabIndex={0}
                    onMouseEnter={() => setHovered(s.sev)}
                    onMouseLeave={() => setHovered(null)}
                    onFocus={() => setHovered(s.sev)}
                    onBlur={() => setHovered(null)}
                  />
                ))}
            </g>
          </svg>

          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
            {hoveredSeg ? (
              <>
                <span className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">{hoveredSeg.value}</span>
                <span className="text-xs text-zinc-500 dark:text-zinc-400">
                  {SEVERITY_LABEL[hoveredSeg.sev]} ({Math.round(hoveredSeg.fraction * 100)}%)
                </span>
              </>
            ) : (
              <>
                <span className="text-2xl font-semibold text-zinc-900 dark:text-zinc-50">{total}</span>
                <span className="text-xs text-zinc-500 dark:text-zinc-400">total</span>
              </>
            )}
          </div>
        </div>

        <ul className="flex w-full min-w-0 flex-col gap-1.5 text-sm">
          {segments.map((s) => (
            <li
              key={s.sev}
              onMouseEnter={() => setHovered(s.sev)}
              onMouseLeave={() => setHovered(null)}
              className={`flex items-center justify-between gap-3 rounded-md px-2 py-1 transition-colors ${
                hovered === s.sev ? "bg-zinc-100 dark:bg-zinc-900" : ""
              }`}
            >
              <span className="flex min-w-0 items-center gap-2 font-medium text-zinc-700 dark:text-zinc-300">
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${SEVERITY_BG_CLASS[s.sev]}`} />
                <span className="truncate">{SEVERITY_LABEL[s.sev]}</span>
              </span>
              <span className="shrink-0 tabular-nums text-zinc-500 dark:text-zinc-400">
                {s.value} ({total > 0 ? Math.round(s.fraction * 100) : 0}%)
              </span>
            </li>
          ))}
        </ul>
      </div>
    </ChartCard>
  );
}
