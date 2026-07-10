"use client";

import { useRouter } from "next/navigation";
import { logout, useAuthUser } from "@/lib/auth";

export default function Navbar() {
  const router = useRouter();
  const user = useAuthUser();

  function handleLogout() {
    logout();
    router.replace("/");
  }

  return (
    <header className="flex items-center justify-between border-b border-zinc-200 bg-white px-6 py-3 dark:border-zinc-800 dark:bg-zinc-950">
      <div className="flex items-center gap-2">
        <span className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">Tenex SOC</span>
        <span className="rounded bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400">
          Dashboard
        </span>
      </div>
      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-2 text-sm">
            <span className="text-zinc-700 dark:text-zinc-300">{user.username}</span>
            <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">
              {user.role}
            </span>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
        >
          Log out
        </button>
      </div>
    </header>
  );
}
