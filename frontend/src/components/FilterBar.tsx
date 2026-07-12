"use client";

import { SEVERITY_ORDER, SEVERITY_BG_CLASS } from "@/lib/severityColors";

export const SEVERITY_OPTIONS = SEVERITY_ORDER;
export const STATUS_OPTIONS = ["new", "reviewed", "dismissed"] as const;

// Severity "on" pills pull their color from the shared severityColors module
// (single source of truth) instead of duplicating hex/named-color choices.
const SEVERITY_ON_STYLE = "text-white border-transparent";

const STATUS_ON_STYLES: Record<string, string> = {
  new: "border-blue-600 bg-blue-600 text-white",
  reviewed: "border-zinc-500 bg-zinc-500 text-white",
  dismissed: "border-zinc-300 bg-zinc-300 text-[#9ca3af] opacity-50",
};

const OFF_STYLE =
  "border-zinc-300 bg-transparent text-zinc-400 dark:border-zinc-700 dark:text-zinc-500";

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

function Pill({ label, on, onStyle, onClick }: { label: string; on: boolean; onStyle: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
        on ? onStyle : OFF_STYLE
      }`}
    >
      {label}
      <span className="text-[9px] opacity-70">▾</span>
    </button>
  );
}

interface FilterBarProps {
  severities: string[];
  statuses: string[];
  onSeverityChange: (next: string[]) => void;
  onStatusChange: (next: string[]) => void;
  onReset: () => void;
}

export default function FilterBar({ severities, statuses, onSeverityChange, onStatusChange, onReset }: FilterBarProps) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-zinc-200 bg-zinc-50/60 p-3 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-wrap items-center gap-2">
        <span className="w-16 shrink-0 text-xs font-medium text-zinc-500 dark:text-zinc-400">Severity:</span>
        {SEVERITY_OPTIONS.map((opt) => (
          <Pill
            key={opt}
            label={opt}
            on={severities.includes(opt)}
            onStyle={`${SEVERITY_BG_CLASS[opt]} ${SEVERITY_ON_STYLE}`}
            onClick={() => onSeverityChange(toggle(severities, opt))}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="w-16 shrink-0 text-xs font-medium text-zinc-500 dark:text-zinc-400">Status:</span>
        {STATUS_OPTIONS.map((opt) => (
          <Pill
            key={opt}
            label={opt}
            on={statuses.includes(opt)}
            onStyle={STATUS_ON_STYLES[opt]}
            onClick={() => onStatusChange(toggle(statuses, opt))}
          />
        ))}
        <button
          type="button"
          onClick={onReset}
          className="ml-auto rounded-md border border-zinc-300 px-2.5 py-1 text-xs font-medium text-zinc-600 transition-colors hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
        >
          Reset Filters
        </button>
      </div>
    </div>
  );
}
