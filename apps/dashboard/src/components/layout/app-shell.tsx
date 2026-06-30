import { Outlet } from "react-router-dom";
import { MobileNav, Sidebar } from "@/components/layout/sidebar";

export function AppShell() {
  return (
    <div className="flex h-screen flex-col overflow-hidden md:grid md:grid-cols-[220px_1fr] md:grid-rows-[var(--shell-header-height)_1fr]">
      <MobileNav />
      <Sidebar className="hidden md:row-span-2 md:grid md:grid-rows-subgrid md:overflow-hidden" />
      <main className="soc-grid-bg flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto md:overflow-hidden md:row-span-2 md:grid md:grid-rows-subgrid">
        <Outlet />
      </main>
    </div>
  );
}
