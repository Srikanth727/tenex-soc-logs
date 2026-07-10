const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

/** Fired whenever the stored session (token/user) changes, so components
 * subscribed via useSyncExternalStore (see lib/auth.ts) can react without
 * polling or an effect-driven setState. */
export const AUTH_CHANGED_EVENT = "tenex-auth-changed";

export function notifyAuthChanged() {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
  }
}

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface ApiFetchOptions extends RequestInit {
  /** Skip the auto-redirect-to-login on 401 (used by the login/signup forms themselves). */
  skipAuthRedirect?: boolean;
}

function getStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("token");
}

function clearSession() {
  window.localStorage.removeItem("token");
  window.localStorage.removeItem("user");
  notifyAuthChanged();
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const { skipAuthRedirect, headers: rawHeaders, ...rest } = options;

  const headers = new Headers(rawHeaders);
  const token = getStoredToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const isFormData = typeof FormData !== "undefined" && rest.body instanceof FormData;
  if (!isFormData && rest.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${API_BASE}${path}`, { ...rest, headers });

  if (res.status === 401) {
    if (typeof window !== "undefined") {
      clearSession();
      if (!skipAuthRedirect) {
        window.location.href = "/";
      }
    }
    throw new ApiError(401, "Session expired. Please log in again.");
  }

  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const message =
      data && typeof data === "object" && "error" in data
        ? String((data as { error: unknown }).error)
        : `Request failed with status ${res.status}`;
    throw new ApiError(res.status, message);
  }

  return data as T;
}
