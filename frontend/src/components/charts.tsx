/**
 * Hand-rolled SVG charts.
 *
 * These are intentionally small and dependency-free: the project has no
 * charting library and adding one for four visualisations would cost more
 * than it returns. Every chart is labelled in text as well as drawn, so the
 * data is available without interpreting the graphic.
 */
import { useId } from "react";
import type { Severity } from "../types/api";
import { SEVERITY_LABEL } from "../lib/domain";

const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  unknown: "var(--sev-unknown)",
};

/* -------------------------------------------------------------- severity */

export interface SeverityDatum {
  severity: Severity;
  count: number;
}

/** Horizontal proportional bars — readable at small sizes and in text. */
export function SeverityBars({ data }: { data: SeverityDatum[] }) {
  const total = data.reduce((sum, item) => sum + item.count, 0);
  if (total === 0) {
    return <p className="chart-empty">No findings have been observed for this organization.</p>;
  }
  return (
    <ul className="severity-bars">
      {data.map(({ severity, count }) => {
        const share = total ? (count / total) * 100 : 0;
        return (
          <li key={severity}>
            <span className="severity-bars-label">
              <i className={`dot sev-${severity}`} aria-hidden="true" />
              {SEVERITY_LABEL[severity]}
            </span>
            <span className="severity-bars-track">
              <span
                className="severity-bars-fill"
                style={{ width: `${share}%`, background: SEVERITY_VAR[severity] }}
              />
            </span>
            <b>{count.toLocaleString()}</b>
          </li>
        );
      })}
    </ul>
  );
}

/* ------------------------------------------------------------------ donut */

export interface DonutSlice {
  label: string;
  value: number;
  color: string;
}

export function Donut({
  slices,
  size = 148,
  thickness = 13,
  centerLabel,
  centerValue,
}: {
  slices: DonutSlice[];
  size?: number;
  thickness?: number;
  centerLabel?: string;
  centerValue?: string | number;
}) {
  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img"
           aria-label={slices.map((slice) => `${slice.label}: ${slice.value}`).join(", ")}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--surface-3)"
          strokeWidth={thickness}
        />
        {total > 0 &&
          slices.map((slice) => {
            const length = (slice.value / total) * circumference;
            const element = (
              <circle
                key={slice.label}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={slice.color}
                strokeWidth={thickness}
                strokeDasharray={`${length} ${circumference - length}`}
                strokeDashoffset={-offset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                strokeLinecap="butt"
              />
            );
            offset += length;
            return element;
          })}
        {(centerValue !== undefined || centerLabel) && (
          <>
            <text
              x="50%"
              y={centerLabel ? "46%" : "52%"}
              textAnchor="middle"
              className="donut-value"
            >
              {centerValue ?? ""}
            </text>
            {centerLabel && (
              <text x="50%" y="62%" textAnchor="middle" className="donut-label">
                {centerLabel}
              </text>
            )}
          </>
        )}
      </svg>
      <ul className="donut-legend">
        {slices.map((slice) => (
          <li key={slice.label}>
            <i style={{ background: slice.color }} aria-hidden="true" />
            {slice.label}
            <b>{slice.value.toLocaleString()}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* -------------------------------------------------------------- sparkline */

/** Trend line for an ordered numeric series. */
export function Sparkline({
  values,
  width = 220,
  height = 48,
  tone = "var(--accent)",
  ariaLabel,
}: {
  values: number[];
  width?: number;
  height?: number;
  tone?: string;
  ariaLabel?: string;
}) {
  const gradientId = useId();
  if (values.length < 2) {
    return <p className="chart-empty">Not enough history to plot a trend.</p>;
  }
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values.map((value, index) => {
    const x = index * stepX;
    const y = height - ((value - min) / span) * (height - 6) - 3;
    return [x, y] as const;
  });
  const line = points.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${line} L${width},${height} L0,${height} Z`;

  return (
    <svg
      className="sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={ariaLabel ?? `Trend from ${values[0]} to ${values[values.length - 1]}`}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={tone} stopOpacity="0.22" />
          <stop offset="100%" stopColor={tone} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${gradientId})`} />
      <path
        d={line}
        fill="none"
        stroke={tone}
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

/* ---------------------------------------------------------------- gauge */

/** Coverage/posture meter expressed as a labelled arc. */
export function Meter({
  value,
  max = 100,
  label,
  tone = "var(--accent)",
}: {
  value: number;
  max?: number;
  label: string;
  tone?: string;
}) {
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  return (
    <div className="meter">
      <div className="meter-track" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max}
           aria-label={label}>
        <div className="meter-fill" style={{ width: `${ratio * 100}%`, background: tone }} />
      </div>
      <div className="meter-caption">
        <span>{label}</span>
        <b>{Math.round(ratio * 100)}%</b>
      </div>
    </div>
  );
}
