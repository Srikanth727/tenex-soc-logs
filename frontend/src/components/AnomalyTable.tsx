"use client";

import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";
import FilterBar, { SEVERITY_OPTIONS, STATUS_OPTIONS } from "@/components/FilterBar";
import { SEVERITY_BADGE_CLASS, isKnownSeverity } from "@/lib/severityColors";

interface AnomalyLogEntry {
  id: number;
  timestamp: string | null;
  cip: string | null;
  login: string | null;
  url: string | null;
  urlcat: string | null;
  threatname: string | null;
}

interface Anomaly {
  id: number;
  rule_name: string;
  mitre_tag: string | null;
  confidence_score: number | null;
  explanation: string | null;
  severity: string | null;
  status: string;
  occurred_at: string | null;
  detected_at: string | null;
  log_entry: AnomalyLogEntry;
}

interface AnomalyTableProps {
  logId: number;
}

function severityBadgeClass(severity: string | null): string {
  return isKnownSeverity(severity) ? SEVERITY_BADGE_CLASS[severity] : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300";
}

function rowOpacityClass(status: string): string {
  if (status === "dismissed") return "opacity-50";
  if (status === "reviewed") return "opacity-60";
  return "";
}

// Dismissed rows mute to a single flat gray instead of keeping each cell's
// normal (varying) text shade — a plain class on the <tr> wouldn't do this,
// since each <td> below sets its own explicit color class that wins over an
// inherited one, so this has to be applied per cell.
const DISMISSED_TEXT = "text-[#9ca3af] dark:text-[#9ca3af]";

function formatDateTime(timestamp: string | null): string {
  if (!timestamp) return "—";
  return new Date(timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

// Severities/statuses the backend ever writes (see rules.yaml / Anomaly.status).
const ALL_SEVERITIES: string[] = [...SEVERITY_OPTIONS];
const ALL_STATUSES: string[] = [...STATUS_OPTIONS];
// Analysts triaging a fresh upload want unreviewed anomalies first.
const DEFAULT_STATUSES: string[] = ["new"];

// Plain data fetch with no state side effects, so both the auto-refetch
// effect and the post-PATCH manual refetch can share it safely.
function fetchFilteredAnomalies(logId: number, severities: string[], statuses: string[]): Promise<Anomaly[]> {
  const params = new URLSearchParams();
  if (severities.length < ALL_SEVERITIES.length) params.set("severity", severities.join(","));
  if (statuses.length < ALL_STATUSES.length) params.set("status", statuses.join(","));
  const qs = params.toString();
  return apiFetch<Anomaly[]>(`/api/logs/${logId}/anomalies${qs ? `?${qs}` : ""}`);
}

export default function AnomalyTable({ logId }: AnomalyTableProps) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severities, setSeverities] = useState<string[]>([...ALL_SEVERITIES]);
  const [statuses, setStatuses] = useState<string[]>(DEFAULT_STATUSES);
  const [toast, setToast] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<number | null>(null);

  const noFiltersSelected = severities.length === 0 || statuses.length === 0;

  // Parent remounts this component (via `key={logId}`) on log switch, so
  // `loading` starts fresh (true) then. For in-place filter changes, the
  // checkbox handlers below set `loading` synchronously (an event handler,
  // not this effect) before the new severities/statuses land here; this
  // effect only ever sets state inside the async fetch's callbacks.
  useEffect(() => {
    if (noFiltersSelected) {
      return; // nothing to fetch; render derives the empty state from noFiltersSelected
    }

    let cancelled = false;
    fetchFilteredAnomalies(logId, severities, statuses)
      .then((data) => {
        if (!cancelled) {
          setAnomalies(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load anomalies.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [logId, noFiltersSelected, severities, statuses]);

  // Total anomaly count for this log file, independent of the current
  // severity/status filters, for the "Showing X of Y" header.
  useEffect(() => {
    let cancelled = false;
    apiFetch<Anomaly[]>(`/api/logs/${logId}/anomalies`)
      .then((data) => {
        if (!cancelled) setTotalCount(data.length);
      })
      .catch(() => {
        /* best-effort — header just omits the "of Y" total on failure */
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  // Auto-dismiss the toast a couple seconds after it appears.
  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 2500);
    return () => clearTimeout(id);
  }, [toast]);

  function handleSeverityChange(next: string[]) {
    setLoading(next.length > 0 && statuses.length > 0);
    setSeverities(next);
  }

  function handleStatusChange(next: string[]) {
    setLoading(next.length > 0 && severities.length > 0);
    setStatuses(next);
  }

  function handleReset() {
    setLoading(true);
    setSeverities([...ALL_SEVERITIES]);
    setStatuses([...DEFAULT_STATUSES]);
  }

  async function handleMarkStatus(anomalyId: number, newStatus: "reviewed" | "dismissed") {
    setUpdatingId(anomalyId);
    try {
      await apiFetch(`/api/anomalies/${anomalyId}`, {
        method: "PATCH",
        body: JSON.stringify({ status: newStatus }),
      });
      setToast(`Marked as ${newStatus}`);
      const data = await fetchFilteredAnomalies(logId, severities, statuses);
      setAnomalies(data);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update anomaly.");
    } finally {
      setUpdatingId(null);
    }
  }

  return (
    <div className="relative rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">
        Detected anomalies
        {totalCount != null && (
          <span className="ml-1.5 font-normal text-zinc-400 dark:text-zinc-500">
            (Showing {noFiltersSelected ? 0 : anomalies.length} of {totalCount})
          </span>
        )}
      </h2>

      <div className="mt-2">
        <FilterBar
          severities={severities}
          statuses={statuses}
          onSeverityChange={handleSeverityChange}
          onStatusChange={handleStatusChange}
          onReset={handleReset}
        />
      </div>

      {/* Initial load (no stale data to keep showing) gets a plain loading line.
          A filter-change refetch instead keeps the old rows visible (dimmed)
          below, so switching filters never flashes an empty/no-match state. */}
      {loading && anomalies.length === 0 && !noFiltersSelected && (
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>
      )}
      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {!loading && !error && (noFiltersSelected || anomalies.length === 0) && (
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
          {noFiltersSelected ? "No filters selected." : "No anomalies match the current filters."}
        </p>
      )}

      {!error && !noFiltersSelected && anomalies.length > 0 && (
        <div
          className={`mt-3 overflow-x-auto transition-opacity duration-150 ${
            loading ? "pointer-events-none opacity-50" : ""
          }`}
        >
          {loading && (
            <p className="mb-2 text-xs font-medium text-zinc-400 dark:text-zinc-500">Refreshing…</p>
          )}
          <table className="w-full min-w-[920px] text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-xs uppercase tracking-wide text-zinc-400 dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">Rule</th>
                <th className="py-2 pr-3 font-medium">MITRE</th>
                <th className="py-2 pr-3 font-medium">Occurred / Detected</th>
                <th className="py-2 pr-3 font-medium">Confidence</th>
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 pr-3 font-medium">Explanation</th>
                <th className="py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {anomalies.map((a) => {
                const dismissed = a.status === "dismissed";
                return (
                <tr key={a.id} className={rowOpacityClass(a.status) || undefined}>
                  <td className="py-2 pr-3 align-top">
                    <span
                      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${severityBadgeClass(a.severity)}`}
                    >
                      {a.severity ?? "unknown"}
                    </span>
                  </td>
                  <td className={`py-2 pr-3 align-top font-medium ${dismissed ? DISMISSED_TEXT : "text-zinc-800 dark:text-zinc-200"}`}>
                    {a.rule_name.replace(/_/g, " ")}
                    {a.status !== "new" && (
                      <span className="ml-1.5 inline-flex rounded-full bg-zinc-200 px-1.5 py-0.5 text-[10px] font-medium capitalize text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">
                        {a.status}
                      </span>
                    )}
                  </td>
                  <td className={`py-2 pr-3 align-top ${dismissed ? DISMISSED_TEXT : "text-zinc-500 dark:text-zinc-400"}`}>{a.mitre_tag ?? "—"}</td>
                  <td className="py-2 pr-3 align-top whitespace-nowrap">
                    <div className={`font-medium ${dismissed ? DISMISSED_TEXT : "text-zinc-800 dark:text-zinc-200"}`}>{formatDateTime(a.occurred_at)}</div>
                    <div className={`text-xs ${dismissed ? DISMISSED_TEXT : "text-zinc-400 dark:text-zinc-500"}`}>
                      detected {formatDateTime(a.detected_at)}
                    </div>
                  </td>
                  <td className={`py-2 pr-3 align-top tabular-nums ${dismissed ? DISMISSED_TEXT : "text-zinc-700 dark:text-zinc-300"}`}>
                    {a.confidence_score != null ? `${Math.round(a.confidence_score * 100)}%` : "—"}
                  </td>
                  <td className={`py-2 pr-3 align-top ${dismissed ? DISMISSED_TEXT : "text-zinc-500 dark:text-zinc-400"}`}>
                    {a.log_entry?.cip ?? "—"}
                    {a.log_entry?.login ? ` · ${a.log_entry.login}` : ""}
                  </td>
                  <td className={`py-2 pr-3 align-top ${dismissed ? DISMISSED_TEXT : "text-zinc-600 dark:text-zinc-400"}`}>{a.explanation ?? "—"}</td>
                  <td className="py-2 align-top">
                    <div className="flex flex-col gap-1">
                      <button
                        type="button"
                        disabled={a.status === "reviewed" || updatingId === a.id}
                        onClick={() => handleMarkStatus(a.id, "reviewed")}
                        className="rounded-md border border-zinc-300 px-2 py-0.5 text-xs font-medium text-zinc-600 transition-colors hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
                      >
                        Mark Reviewed
                      </button>
                      <button
                        type="button"
                        disabled={a.status === "dismissed" || updatingId === a.id}
                        onClick={() => handleMarkStatus(a.id, "dismissed")}
                        className="rounded-md border border-zinc-300 px-2 py-0.5 text-xs font-medium text-zinc-600 transition-colors hover:bg-zinc-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
                      >
                        Dismiss
                      </button>
                    </div>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {toast && (
        <div className="absolute bottom-3 right-3 rounded-md bg-zinc-900 px-3 py-1.5 text-xs font-medium text-white shadow-lg dark:bg-zinc-100 dark:text-zinc-900">
          {toast}
        </div>
      )}
    </div>
  );
}
