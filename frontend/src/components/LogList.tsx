"use client";

import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";
import { useAuthUser } from "@/lib/auth";
import type { LogFileSummary } from "@/app/dashboard/page";

interface LogListProps {
  selectedLogId: number | null;
  onSelect: (id: number) => void;
}

// Parent remounts this component (via `key={refreshSignal}`) to trigger a
// refetch after an upload, so the fetch effect below only needs to run once
// per mount rather than reacting to a signal prop.
export default function LogList({ selectedLogId, onSelect }: LogListProps) {
  const [logs, setLogs] = useState<LogFileSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const isAdmin = useAuthUser()?.role === "admin";

  useEffect(() => {
    let cancelled = false;
    apiFetch<LogFileSummary[]>("/api/logs")
      .then((data) => {
        if (!cancelled) {
          setLogs(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load log files.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Uploaded logs</h2>
        {isAdmin && (
          <span className="text-xs font-medium text-blue-600 dark:text-blue-400">Admin: all analysts</span>
        )}
      </div>

      {loading && <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>}
      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {!loading && !error && logs.length === 0 && (
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">No log files uploaded yet.</p>
      )}

      <ul className="mt-2 flex flex-col divide-y divide-zinc-100 dark:divide-zinc-800">
        {logs.map((log) => (
          <li key={log.id}>
            <button
              onClick={() => onSelect(log.id)}
              className={`flex w-full flex-col gap-0.5 rounded-md px-2 py-2 text-left text-sm transition-colors ${
                selectedLogId === log.id
                  ? "bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300"
                  : "text-zinc-700 hover:bg-zinc-50 dark:text-zinc-300 dark:hover:bg-zinc-900"
              }`}
            >
              <span className="truncate font-medium">{log.filename}</span>
              <span className="text-xs text-zinc-400">
                {log.line_count.toLocaleString()} lines · {log.status}
                {log.uploaded_at ? ` · ${new Date(log.uploaded_at).toLocaleString()}` : ""}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
