export interface Segment {
  label: string;
  value: number;
  color: string;
  // Text drawn on the fill: near-black on light fills (e.g. the amber "warning"), white otherwise.
  textOnFill?: string;
}

interface SegmentedBarProps {
  caption: string;
  segments: Segment[];
}

// One whole split into parts (the block / warn / allow share of all scans). Widths are
// proportional; a part at zero draws nothing. Each part's share is printed inside when it fits,
// and the legend below names every part with its count — so identity never rests on colour alone.
export function SegmentedBar({ caption, segments }: SegmentedBarProps) {
  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const summary = segments
    .map((s) => `${s.label} ${s.value} (${total > 0 ? Math.round((s.value / total) * 100) : 0}%)`)
    .join(", ");

  return (
    <figure>
      <figcaption className="mb-2 font-medium text-slate-800">{caption}</figcaption>
      <div
        role="img"
        aria-label={`${caption}: ${summary}`}
        className="flex w-full gap-[2px] overflow-hidden rounded-lg bg-slate-100"
        style={{ height: 28 }}
      >
        {total === 0
          ? null
          : segments
              .filter((s) => s.value > 0)
              .map((s) => {
                const pct = (s.value / total) * 100;
                return (
                  <div
                    key={s.label}
                    className="flex items-center"
                    style={{ width: `${pct}%`, backgroundColor: s.color }}
                  >
                    {pct >= 8 ? (
                      <span
                        className="px-2 text-xs font-medium whitespace-nowrap"
                        style={{ color: s.textOnFill ?? "#ffffff" }}
                      >
                        {Math.round(pct)}%
                      </span>
                    ) : null}
                  </div>
                );
              })}
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-600">
        {segments.map((s) => (
          <li key={s.label} className="flex items-center gap-1.5">
            <span
              aria-hidden
              className="inline-block h-2.5 w-2.5 rounded-sm"
              style={{ backgroundColor: s.color }}
            />
            {s.label}
            <span className="font-medium text-slate-900 tabular-nums">
              {s.value.toLocaleString()}
            </span>
          </li>
        ))}
      </ul>
    </figure>
  );
}
