// The single HTTP client for all features. The base URL comes from VITE_API_BASE_URL.
import { useEffect, useState } from "react";

const defaultBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const KEY_NAME = "phishguard.apiKey";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export function buildUrl(path: string, baseUrl: string = defaultBaseUrl): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

// The API key stays in this browser tab only: it is gone when the tab closes.
export function saveApiKey(key: string): void {
  sessionStorage.setItem(KEY_NAME, key);
}

export function loadApiKey(): string | null {
  return sessionStorage.getItem(KEY_NAME);
}

export async function apiGet<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = loadApiKey();
  if (key) headers["X-API-Key"] = key;
  const response = await fetch(buildUrl(path), { headers });
  if (!response.ok) {
    throw new ApiError(response.status, `GET ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

// A refusal keeps the API's own reason (FastAPI's "detail"), e.g. "no ethics approval".
export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = loadApiKey();
  if (key) headers["X-API-Key"] = key;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(buildUrl(path), {
    method: "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let detail = `POST ${path} failed with status ${response.status}`;
    try {
      const answer = (await response.json()) as { detail?: unknown };
      if (typeof answer.detail === "string") detail = answer.detail;
      else if (Array.isArray(answer.detail)) detail = "Some fields are missing or not valid.";
    } catch {
      // no JSON body: keep the status message
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

export function explain(error: unknown): string {
  if (error instanceof ApiError && error.status === 401) {
    return "The API key is missing or wrong. Enter it on the sign-in page.";
  }
  if (error instanceof ApiError) return `The API answered with status ${error.status}.`;
  return "The API cannot be reached.";
}

// What a refused POST should say: the API's reason when it gave one.
export function explainRefusal(error: unknown): string {
  if (error instanceof ApiError && error.status !== 401) return error.message;
  return explain(error);
}

export function useApi<T>(path: string, version = 0): ApiState<T> {
  const [state, setState] = useState<ApiState<T>>({ data: null, error: null, loading: true });

  useEffect(() => {
    let current = true;
    apiGet<T>(path)
      .then((data) => {
        if (current) setState({ data, error: null, loading: false });
      })
      .catch((error: unknown) => {
        if (current) setState({ data: null, error: explain(error), loading: false });
      });
    return () => {
      current = false;
    };
  }, [path, version]);

  return state;
}
