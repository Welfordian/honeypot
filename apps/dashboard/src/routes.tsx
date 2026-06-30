import { Navigate, useSearchParams } from "react-router-dom";

const LEGACY_VIEW_MAP: Record<string, string> = {
  live: "/live",
  events: "/search",
  network: "/network",
  ips: "/ips",
  payloads: "/payloads",
  exports: "/exports",
  intel: "/intel",
  actors: "/actors",
  health: "/health",
  hunts: "/hunts",
  docs: "/docs",
  api: "/docs"
};

export function LegacyViewRedirect() {
  const [searchParams] = useSearchParams();
  const view = searchParams.get("view");

  if (view && LEGACY_VIEW_MAP[view]) {
    return <Navigate to={LEGACY_VIEW_MAP[view]} replace />;
  }

  return null;
}
