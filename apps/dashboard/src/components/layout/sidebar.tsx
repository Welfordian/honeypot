import {
  Activity,
  BookOpen,
  Crosshair,
  Download,
  FileWarning,
  Github,
  HeartPulse,
  ListFilter,
  Network,
  ShieldAlert,
  Signal,
  Users
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

export const navItems = [
  { to: "/", label: "Overview", icon: Activity, end: true },
  { to: "/intel", label: "Intel", icon: Crosshair },
  { to: "/actors", label: "Actors", icon: Users },
  { to: "/live", label: "Live", icon: Signal },
  { to: "/search", label: "Search", icon: ListFilter },
  { to: "/network", label: "Network", icon: Network },
  { to: "/ips", label: "IPs", icon: Network },
  { to: "/payloads", label: "Payloads", icon: FileWarning },
  { to: "/health", label: "Health", icon: HeartPulse },
  { to: "/exports", label: "Exports", icon: Download },
  { to: "/docs", label: "API", icon: BookOpen }
] as const;

const GITHUB_URL = "https://github.com/Welfordian/honeypot";

const externalLinkClassName =
  "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors text-muted-foreground hover:bg-border/40 hover:text-foreground";

export function Sidebar({ className }: { className?: string }) {
  return (
    <aside
      className={cn(
        "flex h-full min-h-0 w-[220px] shrink-0 flex-col overflow-hidden border-r border-border bg-card",
        className
      )}
    >
      <div className="shell-header-bar box-border flex items-center gap-2 border-b border-border px-4">
        <ShieldAlert className="h-5 w-5 text-primary" />
        <div className="font-mono text-xs leading-tight">
          <div className="text-primary">◈ HONEYPOT</div>
          <div className="text-muted-foreground">CONSOLE</div>
        </div>
      </div>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <ScrollArea className="min-h-0 flex-1">
          <nav aria-label="Dashboard views" className="flex flex-col gap-1 p-2">
            {navItems.map(({ to, label, icon: Icon, ...rest }) => (
              <NavLink
                key={to}
                to={to}
                end={"end" in rest ? rest.end : false}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-border/40 hover:text-foreground"
                  )
                }
              >
                <Icon className="h-4 w-4" />
                {label}
              </NavLink>
            ))}
          </nav>
        </ScrollArea>
        <div className="shrink-0 border-t border-border px-2 py-2">
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className={externalLinkClassName}
          >
            <Github className="h-4 w-4" />
            GitHub
          </a>
        </div>
      </div>
    </aside>
  );
}

export function MobileNav() {
  return (
    <nav
      aria-label="Dashboard views"
      className="sticky top-0 z-40 border-b border-border bg-card md:hidden"
    >
      <ScrollArea className="w-full whitespace-nowrap">
        <div className="flex gap-1 p-2">
          {navItems.map(({ to, label, icon: Icon, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest ? rest.end : false}
              className={({ isActive }) =>
                cn(
                  "flex min-w-[4.5rem] flex-col items-center gap-1 rounded-md px-2 py-2 text-[10px]",
                  isActive ? "text-primary" : "text-muted-foreground"
                )
              }
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
            </NavLink>
          ))}
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex shrink-0 min-w-[4.5rem] flex-col items-center gap-1 rounded-md px-2 py-2 text-[10px] text-muted-foreground transition-colors hover:bg-border/40 hover:text-foreground"
          >
            <Github className="h-4 w-4" />
            <span>GitHub</span>
          </a>
        </div>
        <ScrollBar orientation="horizontal" />
      </ScrollArea>
    </nav>
  );
}
