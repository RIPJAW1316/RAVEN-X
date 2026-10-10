import { useCallback, useEffect, useState } from "react";

/**
 * Hash-based routing.
 *
 * A hash router keeps deep links working (a finding detail page can be shared
 * or reloaded) without adding a routing dependency to the bundle.
 *
 * Route grammar: `#/section/param/param`
 */
export interface Route {
  section: string;
  params: string[];
}

export const DEFAULT_SECTION = "command";

function parse(hash: string): Route {
  const cleaned = hash.replace(/^#\/?/, "").trim();
  if (!cleaned) return { section: DEFAULT_SECTION, params: [] };
  const parts = cleaned.split("/").filter(Boolean).map(decodeURIComponent);
  return { section: parts[0] ?? DEFAULT_SECTION, params: parts.slice(1) };
}

export function buildHref(section: string, ...params: string[]): string {
  const encoded = params.filter(Boolean).map(encodeURIComponent);
  return `#/${[section, ...encoded].join("/")}`;
}

export function useRoute(): {
  route: Route;
  navigate: (section: string, ...params: string[]) => void;
} {
  const [route, setRoute] = useState<Route>(() => parse(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  const navigate = useCallback((section: string, ...params: string[]) => {
    const next = buildHref(section, ...params);
    if (window.location.hash === next) return;
    window.location.hash = next;
  }, []);

  return { route, navigate };
}
