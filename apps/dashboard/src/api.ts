const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

function apiPath(path: string): string {
  return `${API_BASE_URL.replace(/\/$/, "")}${path}`;
}

export interface ApiClient {
  get<T>(path: string): Promise<T>;
  download(path: string, filename: string): Promise<void>;
}

export function liveStreamUrl(path = "/api/live-stream"): string {
  const origin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const url = new URL(apiPath(path), origin);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

export function createApiClient(): ApiClient {
  async function request(path: string): Promise<Response> {
    const response = await fetch(apiPath(path));
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`${response.status} ${detail}`);
    }
    return response;
  }

  return {
    async get<T>(path: string): Promise<T> {
      return (await request(path)).json() as Promise<T>;
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
