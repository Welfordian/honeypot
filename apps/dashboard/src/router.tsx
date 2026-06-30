import { createBrowserRouter, Navigate } from "react-router-dom";
import { AppShell } from "@/components/layout/app-shell";
import { EventsPage } from "@/pages/events";
import { ExportsPage } from "@/pages/exports";
import { IpDetailPage } from "@/pages/ip-detail";
import { IpsPage } from "@/pages/ips";
import { LivePage } from "@/pages/live";
import { NetworkPage } from "@/pages/network";
import { OverviewPage } from "@/pages/overview";
import { PayloadDetailPage } from "@/pages/payload-detail";
import { PayloadsPage } from "@/pages/payloads";
import { LegacyViewRedirect } from "@/routes";

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
      { path: "live", element: <LivePage /> },
      { path: "search", element: <EventsPage /> },
      { path: "network", element: <NetworkPage /> },
      { path: "ips", element: <IpsPage /> },
      { path: "ips/:ip", element: <IpDetailPage /> },
      { path: "payloads", element: <PayloadsPage /> },
      { path: "payloads/:sha256", element: <PayloadDetailPage /> },
      { path: "exports", element: <ExportsPage /> },
      { path: "*", element: <Navigate to="/" replace /> }
    ]
  }
]);
