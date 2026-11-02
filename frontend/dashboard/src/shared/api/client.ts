// The single HTTP client for all features. The base URL comes from VITE_API_BASE_URL.
const defaultBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

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

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(buildUrl(path), { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new ApiError(response.status, `GET ${path} failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}
