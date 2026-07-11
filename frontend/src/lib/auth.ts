import { useMemo, useSyncExternalStore } from "react";
import { apiFetch, notifyAuthChanged, AUTH_CHANGED_EVENT } from "@/lib/api";

export { ApiError } from "@/lib/api";

export type UserRole = "analyst" | "admin";

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: UserRole;
}

interface AuthResponse {
  token: string;
  user: AuthUser;
}

const TOKEN_KEY = "token";
const USER_KEY = "user";

function persistSession(data: AuthResponse) {
  window.localStorage.setItem(TOKEN_KEY, data.token);
  window.localStorage.setItem(USER_KEY, JSON.stringify(data.user));
  notifyAuthChanged();
}

export async function signup(
  username: string,
  email: string,
  password: string,
  role: UserRole = "analyst"
): Promise<AuthUser> {
  const data = await apiFetch<AuthResponse>("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ username, email, password, role }),
    skipAuthRedirect: true,
  });
  persistSession(data);
  return data.user;
}

export async function login(username: string, password: string): Promise<AuthUser> {
  const data = await apiFetch<AuthResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
    skipAuthRedirect: true,
  });
  persistSession(data);
  return data.user;
}

export function logout() {
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
  notifyAuthChanged();
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getCurrentUser(): AuthUser | null {
  if (typeof window === "undefined") return null;
  const raw = window.localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

function decodeJwtPayload(token: string): { exp?: number } | null {
  try {
    const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = decodeURIComponent(
      atob(base64)
        .split("")
        .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function isTokenValid(token: string | null): boolean {
  if (!token) return false;
  const payload = decodeJwtPayload(token);
  if (!payload?.exp) return true;
  return payload.exp * 1000 > Date.now();
}

/** True if a token is present and not (locally) expired. The API is still the
 * source of truth — apiFetch redirects to login on any 401 regardless. */
export function isAuthenticated(): boolean {
  return isTokenValid(getToken());
}

function subscribeToAuthChanges(callback: () => void): () => void {
  window.addEventListener("storage", callback);
  window.addEventListener(AUTH_CHANGED_EVENT, callback);
  return () => {
    window.removeEventListener("storage", callback);
    window.removeEventListener(AUTH_CHANGED_EVENT, callback);
  };
}

function getServerSnapshotNull(): string | null {
  return null;
}

/** Reactive read of the stored token via useSyncExternalStore, so components
 * don't need an effect+setState to pick up localStorage (which isn't
 * available during SSR) — this is the React-recommended pattern for
 * subscribing to external mutable state without hydration mismatches. */
export function useAuthToken(): string | null {
  return useSyncExternalStore(subscribeToAuthChanges, getToken, getServerSnapshotNull);
}

export function useIsAuthenticated(): boolean {
  const token = useAuthToken();
  return useMemo(() => isTokenValid(token), [token]);
}

function getStoredUserRaw(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(USER_KEY);
}

export function useAuthUser(): AuthUser | null {
  const raw = useSyncExternalStore(subscribeToAuthChanges, getStoredUserRaw, getServerSnapshotNull);
  return useMemo(() => {
    if (!raw) return null;
    try {
      return JSON.parse(raw) as AuthUser;
    } catch {
      return null;
    }
  }, [raw]);
}

function subscribeNever(): () => void {
  return () => {};
}

function getMountedTrue(): boolean {
  return true;
}

function getMountedFalse(): boolean {
  return false;
}

/** True only once the client has hydrated. Server rendering can't know
 * about localStorage, so a component gated on auth (e.g. the login page)
 * should render nothing/a loading state while this is false — otherwise the
 * server-rendered HTML briefly shows the wrong screen before hydration
 * corrects it. */
export function useHasMounted(): boolean {
  return useSyncExternalStore(subscribeNever, getMountedTrue, getMountedFalse);
}
