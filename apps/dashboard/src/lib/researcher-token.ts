export const RESEARCHER_TOKEN_KEY = "honeypot_researcher_token";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

function apiPath(path: string): string {
  return `${API_BASE_URL.replace(/\/$/, "")}${path}`;
}

export function getResearcherToken(): string | null {
  try {
    const value = sessionStorage.getItem(RESEARCHER_TOKEN_KEY)?.trim();
    return value || null;
  } catch {
    return null;
  }
}

export function setResearcherToken(token: string): void {
  sessionStorage.setItem(RESEARCHER_TOKEN_KEY, token.trim());
}

export function clearResearcherToken(): void {
  sessionStorage.removeItem(RESEARCHER_TOKEN_KEY);
}

export function researcherAuthHeaders(): HeadersInit {
  const token = getResearcherToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function downloadResearcherResource(path: string, filename: string): Promise<void> {
  const token = getResearcherToken();
  if (!token) throw new Error("Researcher token not configured for this browser session.");

  const response = await fetch(apiPath(path), {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${detail}`);
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function fetchResearcherJson<T>(path: string): Promise<T> {
  const token = getResearcherToken();
  if (!token) throw new Error("Researcher token not configured for this browser session.");

  const response = await fetch(apiPath(path), {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${response.status} ${detail}`);
  }
  return (await response.json()) as T;
}
