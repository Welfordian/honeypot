import { lazy, Suspense, type ReactNode } from "react";
import { createBrowserRouter, Navigate } from "react-router-dom";
import { AppShell } from "@/components/layout/app-shell";
import { RouteFallback } from "@/components/layout/route-fallback";
import { OverviewPage } from "@/pages/overview";
import { LegacyViewRedirect } from "@/routes";

const IntelPage = lazy(() => import("@/pages/intel").then((m) => ({ default: m.IntelPage })));
const ActorsPage = lazy(() => import("@/pages/actors").then((m) => ({ default: m.ActorsPage })));
const LivePage = lazy(() => import("@/pages/live").then((m) => ({ default: m.LivePage })));
const EventsPage = lazy(() => import("@/pages/events").then((m) => ({ default: m.EventsPage })));
const NetworkPage = lazy(() => import("@/pages/network").then((m) => ({ default: m.NetworkPage })));
const IpsPage = lazy(() => import("@/pages/ips").then((m) => ({ default: m.IpsPage })));
const IpDetailPage = lazy(() => import("@/pages/ip-detail").then((m) => ({ default: m.IpDetailPage })));
const PayloadsPage = lazy(() => import("@/pages/payloads").then((m) => ({ default: m.PayloadsPage })));
const PayloadDetailPage = lazy(() =>
  import("@/pages/payload-detail").then((m) => ({ default: m.PayloadDetailPage }))
);
const HealthPage = lazy(() => import("@/pages/health").then((m) => ({ default: m.HealthPage })));
const HuntsPage = lazy(() => import("@/pages/hunts").then((m) => ({ default: m.HuntsPage })));
const ExportsPage = lazy(() => import("@/pages/exports").then((m) => ({ default: m.ExportsPage })));
const DocsPage = lazy(() => import("@/pages/docs").then((m) => ({ default: m.DocsPage })));
const NotFoundPage = lazy(() => import("@/pages/not-found").then((m) => ({ default: m.NotFoundPage })));

function lazyRoute(element: ReactNode) {
  return <Suspense fallback={<RouteFallback />}>{element}</Suspense>;
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      {
        index: true,
        element: (
          <>
            <LegacyViewRedirect />
            <OverviewPage />
          </>
        )
      },
      { path: "intel", element: lazyRoute(<IntelPage />) },
      { path: "actors", element: lazyRoute(<ActorsPage />) },
      { path: "live", element: lazyRoute(<LivePage />) },
      { path: "search", element: lazyRoute(<EventsPage />) },
      { path: "network", element: lazyRoute(<NetworkPage />) },
      { path: "ips", element: lazyRoute(<IpsPage />) },
      { path: "ips/:ip", element: lazyRoute(<IpDetailPage />) },
      { path: "payloads", element: lazyRoute(<PayloadsPage />) },
      { path: "payloads/:sha256", element: lazyRoute(<PayloadDetailPage />) },
      { path: "health", element: lazyRoute(<HealthPage />) },
      { path: "hunts", element: lazyRoute(<HuntsPage />) },
      { path: "exports", element: lazyRoute(<ExportsPage />) },
      { path: "docs", element: lazyRoute(<DocsPage />) },
      { path: "api", element: <Navigate to="/docs" replace /> },
      { path: "*", element: lazyRoute(<NotFoundPage />) }
    ]
  }
]);
