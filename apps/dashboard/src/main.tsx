import { QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import { TooltipProvider } from "@/components/ui/tooltip";
import { overviewChartsQueryOptions, overviewSummaryQueryOptions } from "@/hooks/use-queries";
import { queryClient } from "@/lib/query-client";
import { router } from "@/router";
import "./index.css";

void Promise.all([
  queryClient.prefetchQuery(overviewSummaryQueryOptions),
  queryClient.prefetchQuery(overviewChartsQueryOptions)
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <RouterProvider router={router} />
      </TooltipProvider>
    </QueryClientProvider>
  </React.StrictMode>
);
