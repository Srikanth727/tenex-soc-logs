"use client";

import { ChangeEvent, useRef, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";
import type { LogFileSummary } from "@/app/dashboard/page";

interface UploadResult extends LogFileSummary {
  anomaly_count: number;
}

interface UploadProps {
  onUploaded: (log: LogFileSummary) => void;
}

export default function Upload({ onUploaded }: UploadProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<UploadResult | null>(null);

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError(null);
    setLastResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const result = await apiFetch<UploadResult>("/api/logs", {
        method: "POST",
        body: formData,
      });
      setLastResult(result);
      onUploaded(result);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Upload failed. Try again.");
    } finally {
      setUploading(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  }

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Upload Zscaler log</h2>
      <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
        Pipe-delimited NSS Web Proxy log file (.log, .txt).
      </p>

      <label className="mt-3 flex cursor-pointer flex-col items-center justify-center gap-1 rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500 transition-colors hover:border-blue-500 hover:text-blue-600 dark:border-zinc-700 dark:text-zinc-400">
        <span>{uploading ? "Uploading…" : "Click to choose a file"}</span>
        <input
          ref={inputRef}
          type="file"
          accept=".log,.txt"
          className="hidden"
          onChange={handleFileChange}
          disabled={uploading}
        />
      </label>

      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {lastResult && !error && (
        <p className="mt-2 text-sm text-green-700 dark:text-green-400">
          Parsed {lastResult.line_count.toLocaleString()} lines, flagged{" "}
          {lastResult.anomaly_count.toLocaleString()} anomalies.
        </p>
      )}
    </div>
  );
}
