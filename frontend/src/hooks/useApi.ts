import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export interface AsyncState<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  /** Re-run the loader, keeping the previous data visible while it refreshes. */
  reload: () => void;
}

function toApiError(reason: unknown): ApiError {
  if (reason instanceof ApiError) return reason;
  const message = reason instanceof Error ? reason.message : "Unexpected client error";
  return new ApiError(message, 0);
}

/**
 * Run an aborting async loader whenever `deps` change.
 *
 * `loader` receives an AbortSignal; passing it to the API layer prevents a
 * slow response for a previous organization from overwriting fresh data.
 */
export function useApi<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  deps: ReadonlyArray<unknown>,
  options: { enabled?: boolean } = {},
): AsyncState<T> {
  const enabled = options.enabled ?? true;
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [loading, setLoading] = useState(enabled);
  const [nonce, setNonce] = useState(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  useEffect(() => {
    if (!enabled) {
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    loaderRef
      .current(controller.signal)
      .then((value) => {
        if (!active) return;
        setData(value);
        setError(undefined);
      })
      .catch((reason: unknown) => {
        if (!active || controller.signal.aborted) return;
        setError(toApiError(reason));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, nonce]);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  return { data, error, loading, reload };
}

/**
 * Poll `reload` on an interval. Polling pauses while the tab is hidden so a
 * background tab does not keep hitting the control plane.
 */
export function usePolling(reload: () => void, intervalMs: number, enabled: boolean): void {
  useEffect(() => {
    if (!enabled || intervalMs <= 0) return;
    let timer: number | undefined;
    const tick = () => {
      if (!document.hidden) reload();
    };
    timer = window.setInterval(tick, intervalMs);
    return () => {
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [reload, intervalMs, enabled]);
}

/** Track an in-flight mutation so buttons can disable and surface failures. */
export function useMutation<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
): {
  run: (...args: TArgs) => Promise<TResult | undefined>;
  busy: boolean;
  error: ApiError | undefined;
  reset: () => void;
} {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const actionRef = useRef(action);
  actionRef.current = action;

  const run = useCallback(async (...args: TArgs) => {
    setBusy(true);
    setError(undefined);
    try {
      return await actionRef.current(...args);
    } catch (reason: unknown) {
      setError(toApiError(reason));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);

  const reset = useCallback(() => setError(undefined), []);
  return { run, busy, error, reset };
}
