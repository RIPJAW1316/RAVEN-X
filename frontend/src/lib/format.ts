/** Presentation helpers. All of these return "—" for absent data. */

export const DASH = "—";

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return DASH;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return DASH;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return "never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return DASH;
  const seconds = Math.round((Date.now() - date.getTime()) / 1000);
  const future = seconds < 0;
  const magnitude = Math.abs(seconds);
  const units: Array<[number, string]> = [
    [60, "second"],
    [3600, "minute"],
    [86400, "hour"],
    [2592000, "day"],
  ];
  let text: string;
  if (magnitude < 60) text = `${magnitude}s`;
  else if (magnitude < 3600) text = `${Math.floor(magnitude / 60)}m`;
  else if (magnitude < 86400) text = `${Math.floor(magnitude / 3600)}h`;
  else text = `${Math.floor(magnitude / 86400)}d`;
  void units;
  return future ? `in ${text}` : `${text} ago`;
}

/** Short identifier rendering: `a1b2c3d4…f8e9`. */
export function shortId(value: string | null | undefined): string {
  if (!value) return DASH;
  return value.length <= 16 ? value : `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function titleCase(value: string | null | undefined): string {
  if (!value) return DASH;
  return value
    .replace(/[_.]/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return DASH;
  return value.toLocaleString();
}

export function formatDuration(from: string | null, to: string | null): string {
  if (!from || !to) return DASH;
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return DASH;
  const seconds = Math.round((end - start) / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function percent(part: number, whole: number): number {
  if (!whole) return 0;
  return Math.round((part / whole) * 100);
}
