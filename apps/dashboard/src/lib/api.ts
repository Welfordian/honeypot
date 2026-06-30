const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

function apiPath(path: string): string {
  return `${API_BASE_URL.replace(/\/$/, "")}${path}`;
}

export interface ApiClient {
  get<T>(path: string, headers?: Record<string, string>): Promise<T>;
  download(path: string, filename: string): Promise<void>;
  post<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T>;
  delete<T>(path: string, headers?: Record<string, string>): Promise<T>;
}

export function liveStreamUrl(path = "/api/live-stream"): string {
  const origin = typeof window === "undefined" ? "https://dashboard.example.com" : window.location.origin;
  const url = new URL(apiPath(path), origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export function createApiClient(): ApiClient {
  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    const response = await fetch(apiPath(path), init);
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`${response.status} ${detail}`);
    }
    return response;
  }

  return {
    async get<T>(path: string, headers: Record<string, string> = {}): Promise<T> {
      return (await request(path, { headers })).json() as Promise<T>;
    },
    async post<T>(path: string, body: unknown, headers: Record<string, string> = {}): Promise<T> {
      const response = await fetch(apiPath(path), {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body)
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`${response.status} ${detail}`);
      }
      return response.json() as Promise<T>;
    },
    async delete<T>(path: string, headers: Record<string, string> = {}): Promise<T> {
      const response = await fetch(apiPath(path), { method: "DELETE", headers });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`${response.status} ${detail}`);
      }
      return response.json() as Promise<T>;
    },
    async download(path: string, filename: string): Promise<void> {
      const blob = await (await request(path)).blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
    }
  };
}

export const api = createApiClient();
