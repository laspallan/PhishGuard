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
  if (state.loading) return <p className="text-sm text-slate-600">Loading…</p>;
  if (state.error) {
    return (
      <p role="alert" className="rounded border border-slate-300 p-3 text-sm">
        {state.error}
      </p>
    );
  }
  if (state.data === null || isEmpty?.(state.data)) {
    return <p className="text-sm text-slate-600">{emptyMessage ?? "Nothing yet."}</p>;
  }
  return <>{children(state.data)}</>;
}

interface StatProps {
  label: string;
  value: string;
}

export function Stat({ label, value }: StatProps) {
  return (
    <div className="rounded border border-slate-200 p-4">
      <p className="text-sm text-slate-600">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
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
        <caption className="mb-2 text-left font-medium">{caption}</caption>
        <thead>
          <tr className="border-b border-slate-300">
            {headers.map((header) => (
              <th key={header} scope="col" className="px-2 py-1 font-medium">
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-b border-slate-100">
              {row.map((cell, column) => (
                <td key={column} className="px-2 py-1 tabular-nums">
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
