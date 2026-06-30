import { useCallback, useState } from "react";
import type { EventRow } from "@/types/api";

export function useEventInspector() {
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null);

  const openEvent = useCallback((event: EventRow) => {
    setSelectedEvent(event);
  }, []);

  const closeEvent = useCallback(() => {
    setSelectedEvent(null);
  }, []);

  return { selectedEvent, openEvent, closeEvent };
}
