"use client";

import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";

interface ChainEvent {
  rule: string;
  mitre_tag: string | null;
  confidence: number | null;
  severity: string | null;
  timestamp: string | null;
  explanation: string | null;
}

interface Chain {
  entity_type: "ip" | "user";
  entity_value: string;
  anomalies_count: number;
  anomalies: ChainEvent[];
  highest_severity: string | null;
  chain_synthesis: string;
}

interface ChainListProps {
  logId: number;
}

const SEVERITY_ACCENT: Record<string, string> = {
  critical: "border-l-red-500 bg-red-50/60 dark:bg-red-950/20",
  high: "border-l-orange-500 bg-orange-50/60 dark:bg-orange-950/20",
  medium: "border-l-yellow-500 bg-yellow-50/60 dark:bg-yellow-950/20",
  low: "border-l-zinc-400 bg-zinc-50/60 dark:bg-zinc-900/40",
};

function accentClass(severity: string | null): string {
  return SEVERITY_ACCENT[(severity ?? "").toLowerCase()] ?? SEVERITY_ACCENT.low;
}

function formatTime(timestamp: string | null): string {
  if (!timestamp) return "unknown time";
  return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatTimeRange(anomalies: ChainEvent[]): string {
  if (anomalies.length === 0) return "";
  const first = formatTime(anomalies[0].timestamp);
  const last = formatTime(anomalies[anomalies.length - 1].timestamp);
  return first === last ? first : `${first}–${last}`;
}

const TIMELINE_PREVIEW_COUNT = 6;

function ChainCard({ chain }: { chain: Chain }) {
  const [expanded, setExpanded] = useState(true);
  const [showAllEvents, setShowAllEvents] = useState(false);

  const hasMoreEvents = chain.anomalies.length > TIMELINE_PREVIEW_COUNT;
  const visibleEvents = showAllEvents ? chain.anomalies : chain.anomalies.slice(0, TIMELINE_PREVIEW_COUNT);

  return (
    <div
      className={`rounded-lg border border-l-4 border-zinc-200 dark:border-zinc-800 ${accentClass(chain.highest_severity)}`}
    >
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-start justify-between gap-3 p-4 text-left">
        <div>
          <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">
            Suspicious activity chain: {chain.entity_value}{" "}
            <span className="font-normal text-zinc-500 dark:text-zinc-400">
              ({chain.anomalies_count} correlated events, {formatTimeRange(chain.anomalies)})
            </span>
          </p>
          <p className="mt-0.5 text-xs uppercase tracking-wide text-zinc-400">
            {chain.entity_type === "ip" ? "Source IP" : "User account"}
          </p>
        </div>
        <span className="mt-0.5 shrink-0 text-zinc-400">{expanded ? "▾" : "▸"}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-4">
          <ol className="flex flex-col gap-2 border-l-2 border-zinc-300 pl-4 dark:border-zinc-700">
            {visibleEvents.map((a, i) => (
              <li key={i} className="relative text-sm">
                <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-zinc-400 dark:bg-zinc-600" />
                <span className="font-medium text-zinc-800 dark:text-zinc-200">{a.rule.replace(/_/g, " ")}</span>{" "}
                <span className="text-zinc-500 dark:text-zinc-400">
                  &middot; {a.mitre_tag ?? "—"} &middot; {formatTime(a.timestamp)} &middot;{" "}
                  {a.confidence != null ? `${Math.round(a.confidence * 100)}%` : "—"}
                </span>
              </li>
            ))}
          </ol>

          {hasMoreEvents && (
            <button
              onClick={() => setShowAllEvents((v) => !v)}
              className="ml-4 mt-2 text-xs font-medium text-blue-600 hover:underline dark:text-blue-400"
            >
              {showAllEvents ? "Show fewer events" : `Show all ${chain.anomalies.length} events`}
            </button>
          )}

          <p className="mt-3 text-sm italic text-zinc-600 dark:text-zinc-400">{chain.chain_synthesis}</p>
        </div>
      )}
    </div>
  );
}

export default function ChainList({ logId }: ChainListProps) {
  const [chains, setChains] = useState<Chain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Parent remounts this component (via `key={logId}`) whenever the selected
  // log changes, so state (including `loading`) already starts fresh — this
  // effect only needs to run once per mount.
  useEffect(() => {
    let cancelled = false;
    apiFetch<Chain[]>(`/api/logs/${logId}/chains`)
      .then((data) => {
        if (!cancelled) {
          setChains(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load attack chains.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  // Nothing to show once resolved with zero chains -- the flat AnomalyTable
  // below already covers this data, so ChainList stays fully out of the way.
  if (!loading && !error && chains.length === 0) {
    return null;
  }

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">
        Attack chains{!loading && !error ? ` (${chains.length})` : ""}
      </h2>

      {loading && (
        <div className="rounded-xl border border-zinc-200 bg-white p-4 text-sm text-zinc-500 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400">
          Correlating anomalies into attack chains&hellip;
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-zinc-200 bg-white p-4 text-sm text-red-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && chains.map((chain) => <ChainCard key={`${chain.entity_type}-${chain.entity_value}`} chain={chain} />)}
    </div>
  );
}
