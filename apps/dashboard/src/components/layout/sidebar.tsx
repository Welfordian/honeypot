import {
  Activity,
  Download,
  FileWarning,
  ListFilter,
  Network,
  ShieldAlert,
  Signal
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

export const navItems = [
  { to: "/", label: "Overview", icon: Activity, end: true },
  { to: "/live", label: "Live", icon: Signal },
  { to: "/search", label: "Search", icon: ListFilter },
  { to: "/network", label: "Network", icon: Network },
  { to: "/ips", label: "IPs", icon: Network },
  { to: "/payloads", label: "Payloads", icon: FileWarning },
  { to: "/exports", label: "Exports", icon: Download }
] as const;

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
    </aside>
  );
}

export function MobileNav() {
  return (
    <nav
      aria-label="Dashboard views"
      className="sticky top-0 z-40 grid grid-cols-4 gap-1 border-b border-border bg-card p-2 md:hidden"
    >
      {navItems.map(({ to, label, icon: Icon, ...rest }) => (
        <NavLink
          key={to}
          to={to}
          end={"end" in rest ? rest.end : false}
          className={({ isActive }) =>
            cn(
              "flex flex-col items-center gap-1 rounded-md px-1 py-2 text-[10px]",
              isActive ? "text-primary" : "text-muted-foreground"
            )
          }
        >
          <Icon className="h-4 w-4" />
          <span>{label}</span>
        </NavLink>
      ))}
    </nav>
  );
}
