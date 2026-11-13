import type { ReactNode } from "react";

import type { ApiState } from "@/shared/api/client";

interface DataStateProps<T> {
  state: ApiState<T>;
  isEmpty?: (data: T) => boolean;
  emptyMessage?: string;
  children: (data: T) => ReactNode;
}

// One place for "loading", "failed" and "nothing yet": a page never shows invented numbers.
export function DataState<T>({ state, isEmpty, emptyMessage, children }: DataStateProps<T>) {
  if (state.loading) {
    return (
      <p className="flex items-center gap-2 text-sm text-slate-600">
        <span
          aria-hidden
          className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-slate-300 border-t-slate-600"
        />
        Loading…
      </p>
    );
  }
  if (state.error) {
    return (
      <p
        role="alert"
        className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800"
      >
        {state.error}
      </p>
    );
  }
  if (state.data === null || isEmpty?.(state.data)) {
    return (
      <p className="rounded-lg border border-dashed border-slate-300 bg-white p-6 text-center text-sm text-slate-500">
        {emptyMessage ?? "Nothing yet."}
      </p>
    );
  }
  return <>{children(state.data)}</>;
}

export type Tone = "neutral" | "good" | "warning" | "serious" | "critical";

const toneColor: Record<Tone, string> = {
  neutral: "var(--series-1)",
  good: "var(--status-good)",
  warning: "var(--status-warning)",
  serious: "var(--status-serious)",
  critical: "var(--status-critical)",
};

interface StatProps {
  label: string;
  value: string;
  hint?: string;
  tone?: Tone;
}

// A KPI tile: label, value, an optional one-line hint, and an optional status dot (the dot never
// carries meaning alone — the label always names what it is).
export function Stat({ label, value, hint, tone = "neutral" }: StatProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center gap-2">
        {tone !== "neutral" ? (
          <span
            aria-hidden
            className="inline-block h-2.5 w-2.5 shrink-0 rounded-full"
            style={{ backgroundColor: toneColor[tone] }}
          />
        ) : null}
        <p className="text-sm text-slate-600">{label}</p>
      </div>
      <p className="mt-2 text-2xl font-semibold text-slate-900">{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

interface HeroStatProps {
  label: string;
  value: string;
  hint?: string;
}

// The single lead number a dashboard opens with: one per view.
export function HeroStat({ label, value, hint }: HeroStatProps) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm text-slate-600">{label}</p>
      <p className="mt-1 text-5xl leading-none font-semibold text-slate-900">{value}</p>
      {hint ? <p className="mt-2 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

interface DataTableProps {
  caption: string;
  headers: string[];
  rows: (string | number)[][];
}

export function DataTable({ caption, headers, rows }: DataTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="mb-2 text-left font-medium text-slate-800">{caption}</caption>
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50 text-slate-600">
            {headers.map((header) => (
              <th key={header} scope="col" className="px-3 py-2 font-medium">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
              {row.map((cell, column) => (
                <td key={column} className="px-3 py-2 tabular-nums">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
