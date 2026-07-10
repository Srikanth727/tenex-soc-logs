"use client";

import { ReactNode, useEffect, useMemo, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";

interface TimelineBucket {
  timestamp: string | null;
  count: number;
}

interface TimelineProps {
  logId: number;
}

const CHART_HEIGHT = 160;
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

function ChartCard({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Request volume by hour</h2>
      <div className="mt-3">{children}</div>
    </div>
  );
}

export default function Timeline({ logId }: TimelineProps) {
  const [buckets, setBuckets] = useState<TimelineBucket[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);

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
      <div className="flex gap-3">
        <div
          className="flex flex-col justify-between text-xs text-[#898781] tabular-nums"
          style={{ height: CHART_HEIGHT }}
        >
          {yTicks
            .slice()
            .reverse()
            .map((t) => (
              <span key={t}>{t.toLocaleString()}</span>
            ))}
        </div>

        <div className="flex-1 overflow-x-auto">
          <div
            className="relative flex items-end border-b border-[#c3c2b7] dark:border-[#383835]"
            style={{ height: CHART_HEIGHT, gap: BAR_GAP }}
          >
            {yTicks.slice(1).map((t) => (
              <div
                key={t}
                className="pointer-events-none absolute left-0 right-0 border-t border-[#e1e0d9] dark:border-[#2c2c2a]"
                style={{ bottom: (t / scaleMax) * CHART_HEIGHT }}
              />
            ))}

            {buckets.map((b, i) => {
              const barHeight = Math.max(2, (b.count / scaleMax) * CHART_HEIGHT);
              return (
                <div
                  key={b.timestamp ?? i}
                  className="relative flex flex-shrink-0 flex-col items-center justify-end outline-none"
                  style={{ width: BAR_WIDTH, height: CHART_HEIGHT }}
                  tabIndex={0}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}
                  onFocus={() => setHovered(i)}
                  onBlur={() => setHovered(null)}
                >
                  {hovered === i && (
                    <div className="absolute bottom-full z-10 mb-2 whitespace-nowrap rounded-md bg-zinc-900 px-2 py-1 text-xs text-white shadow-lg dark:bg-zinc-100 dark:text-zinc-900">
                      <span className="font-semibold tabular-nums">{b.count.toLocaleString()}</span>{" "}
                      <span className="opacity-70">{formatFullLabel(b.timestamp)}</span>
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

          <div className="mt-1 flex" style={{ gap: BAR_GAP }}>
            {buckets.map((b, i) => (
              <div
                key={b.timestamp ?? i}
                className="flex flex-shrink-0 justify-center whitespace-nowrap text-[10px] text-[#898781]"
                style={{ width: BAR_WIDTH }}
              >
                {i % step === 0 ? formatHourLabel(b.timestamp) : ""}
              </div>
            ))}
          </div>
        </div>
      </div>
    </ChartCard>
  );
}
