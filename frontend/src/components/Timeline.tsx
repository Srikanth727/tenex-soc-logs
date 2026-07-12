"use client";

import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";

interface TimelineBucket {
  timestamp: string | null;
  count: number;
}

interface TimelineProps {
  logId: number;
}

// Floor for the bars area before it's been measured (and if the card ever
// renders shorter than this for some reason) — actual height comes from
// ResizeObserver below, so the chart fills whatever the grid row gives it
// instead of leaving blank space when the SeverityChart sibling is taller.
const MIN_CHART_HEIGHT = 160;
const BAR_WIDTH = 20;
const BAR_GAP = 2;

function niceTicks(max: number, targetCount = 4): number[] {
  if (max <= 0) return [0, 1];
  const rawStep = max / targetCount;
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
  const residual = rawStep / magnitude;
  let step: number;
  if (residual > 5) step = 10 * magnitude;
  else if (residual > 2) step = 5 * magnitude;
  else if (residual > 1) step = 2 * magnitude;
  else step = magnitude;
  // Counts are integers, so a sub-1 step would round multiple ticks to the
  // same value (e.g. 0.5 and 1 both round to 1) and produce duplicate keys.
  step = Math.max(1, Math.round(step));

  const ticks: number[] = [];
  for (let v = 0; v <= max + step; v += step) {
    ticks.push(v);
  }
  return ticks;
}

function labelEvery(n: number): number {
  if (n <= 12) return 1;
  if (n <= 36) return 3;
  if (n <= 72) return 6;
  return 12;
}

function formatHourLabel(timestamp: string | null): string {
  if (!timestamp) return "";
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", hour12: false });
}

function formatFullLabel(timestamp: string | null): string {
  if (!timestamp) return "Unknown time";
  return new Date(timestamp).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Each bucket is the start of an hour (backend groups by date_trunc('hour', ...)),
// so the tooltip's range is [bucket, bucket + 1h) — e.g. "06:00–07:00".
function formatHourRange(timestamp: string | null): string {
  if (!timestamp) return "Unknown time";
  const start = new Date(timestamp);
  const end = new Date(start.getTime() + 60 * 60 * 1000);
  const fmt = (d: Date) => d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return `${fmt(start)}–${fmt(end)}`;
}

function ChartCard({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full min-h-0 flex-col rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="shrink-0 text-sm font-semibold text-zinc-900 dark:text-zinc-50">Request volume by hour</h2>
      <div className="mt-3 flex min-h-0 flex-1 flex-col">{children}</div>
    </div>
  );
}

export default function Timeline({ logId }: TimelineProps) {
  const [buckets, setBuckets] = useState<TimelineBucket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);
  const barsAreaRef = useRef<HTMLDivElement>(null);
  const [chartHeight, setChartHeight] = useState(MIN_CHART_HEIGHT);

  // Parent remounts this component (via `key={logId}`) whenever the selected
  // log changes, so state (including `loading`) already starts fresh — this
  // effect only needs to run once per mount.
  useEffect(() => {
    let cancelled = false;
    apiFetch<TimelineBucket[]>(`/api/logs/${logId}/timeline`)
      .then((data) => {
        if (!cancelled) {
          setBuckets(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load timeline.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  // Measures the bars area's actual rendered height (it's flex-1, no fixed
  // height) so the chart grows to fill the grid row instead of staying a
  // fixed 160px and leaving blank space when SeverityChart is taller.
  useEffect(() => {
    const el = barsAreaRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height;
      if (h) setChartHeight(Math.max(MIN_CHART_HEIGHT, h));
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  const maxCount = useMemo(() => Math.max(1, ...buckets.map((b) => b.count)), [buckets]);
  const yTicks = useMemo(() => niceTicks(maxCount), [maxCount]);
  const scaleMax = yTicks[yTicks.length - 1];
  const step = labelEvery(buckets.length);

  if (loading) {
    return (
      <ChartCard>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading timeline…</p>
      </ChartCard>
    );
  }
  if (error) {
    return (
      <ChartCard>
        <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
      </ChartCard>
    );
  }
  if (buckets.length === 0) {
    return (
      <ChartCard>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">No activity recorded for this log.</p>
      </ChartCard>
    );
  }

  return (
    <ChartCard>
      <div className="flex min-h-0 flex-1 gap-3">
        <div className="flex items-center">
          <span
            className="shrink-0 whitespace-nowrap text-[10px] font-medium uppercase tracking-wide text-[#898781]"
            style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}
          >
            Requests per hour
          </span>
        </div>
        <div className="flex flex-col justify-between text-xs text-[#898781] tabular-nums">
          {yTicks
            .slice()
            .reverse()
            .map((t) => (
              <span key={t}>{t.toLocaleString()}</span>
            ))}
        </div>

        <div className="flex min-w-0 flex-1 flex-col overflow-x-auto">
          <div
            ref={barsAreaRef}
            className="relative flex flex-1 items-end border-b border-[#c3c2b7] dark:border-[#383835]"
            style={{ gap: BAR_GAP }}
          >
            {yTicks.slice(1).map((t) => (
              <div
                key={t}
                className="pointer-events-none absolute left-0 right-0 border-t border-[#e1e0d9] dark:border-[#2c2c2a]"
                style={{ bottom: (t / scaleMax) * chartHeight }}
              />
            ))}

            {buckets.map((b, i) => {
              const barHeight = Math.max(2, (b.count / scaleMax) * chartHeight);
              return (
                <div
                  key={b.timestamp ?? i}
                  className="relative flex h-full flex-shrink-0 flex-col items-center justify-end outline-none"
                  style={{ width: BAR_WIDTH }}
                  tabIndex={0}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(i)}
                  onBlur={() => setHovered(null)}
                >
                  {hovered === i && (
                    <div className="absolute bottom-full z-10 mb-2 whitespace-nowrap rounded-md bg-zinc-900 px-2 py-1 text-xs text-white shadow-lg dark:bg-zinc-100 dark:text-zinc-900">
                      <span className="font-semibold tabular-nums">{formatHourRange(b.timestamp)}</span>
                      {" · "}
                      <span className="tabular-nums">{b.count.toLocaleString()}</span> requests
                      <div className="opacity-70">{formatFullLabel(b.timestamp)}</div>
                    </div>
                  )}
                  <div
                    className="w-full rounded-t bg-[#2a78d6] transition-opacity dark:bg-[#3987e5]"
                    style={{
                      height: barHeight,
                      opacity: hovered === null || hovered === i ? 1 : 0.55,
                    }}
                  />
                </div>
              );
            })}
          </div>

          <div className="mt-1 flex shrink-0" style={{ gap: BAR_GAP }}>
            {buckets.map((b, i) => (
              <div
                key={b.timestamp ?? i}
                className="flex flex-shrink-0 justify-center whitespace-nowrap text-[10px] text-[#898781]"
                style={{ width: BAR_WIDTH }}
              >
                {/* Sparse-labeled by design (labelEvery): showing all 24 hours
                    would overlap at typical bucket counts, so only every
                    Nth tick renders — hovering any bar still shows its exact
                    hour range via the tooltip above. */}
                {i % step === 0 ? formatHourLabel(b.timestamp) : ""}
              </div>
            ))}
          </div>
          <p className="mt-1.5 shrink-0 text-center text-[10px] font-medium uppercase tracking-wide text-[#898781]">
            Hour of day (24-hour format)
          </p>
        </div>
      </div>
    </ChartCard>
  );
}
