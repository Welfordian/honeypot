import { useEffect, useRef, useState } from "react";
import { api, liveStreamUrl } from "@/lib/api";
import { isEventRow, mergeLiveEvent } from "@/lib/utils";
import type { EventRow, LiveStatus } from "@/types/api";

export function useLiveStream() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [lastUpdate, setLastUpdate] = useState("");
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const reconnectAttempt = useRef(0);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let pingTimer: number | undefined;

    const clearPing = () => {
      if (pingTimer !== undefined) window.clearInterval(pingTimer);
      pingTimer = undefined;
    };

    const scheduleReconnect = () => {
      clearPing();
      if (cancelled) return;
      setStatus("reconnecting");
      const delay = Math.min(30000, 1000 * 2 ** reconnectAttempt.current);
      reconnectAttempt.current += 1;
      reconnectTimer = window.setTimeout(connect, delay);
    };

    const connect = () => {
      if (cancelled) return;
      setStatus(reconnectAttempt.current ? "reconnecting" : "connecting");
      socket = new WebSocket(liveStreamUrl());

      socket.addEventListener("open", () => {
        reconnectAttempt.current = 0;
        setStatus("live");
        setLastUpdate(new Date().toISOString());
        clearPing();
        pingTimer = window.setInterval(() => {
          if (socket?.readyState === WebSocket.OPEN) socket.send("ping");
        }, 25000);
      });

      socket.addEventListener("message", (event) => {
        if (typeof event.data !== "string") return;
        let message: { type?: string; event?: unknown; at?: string };
        try {
          message = JSON.parse(event.data) as { type?: string; event?: unknown; at?: string };
        } catch {
          return;
        }

        if (message.type === "event" && isEventRow(message.event)) {
          const streamedEvent = message.event;
          setEvents((current) => mergeLiveEvent(current, streamedEvent));
          setLastUpdate(message.at ?? streamedEvent.received_at);
          setStatus("live");
          return;
        }

        if (message.type === "connected" || message.type === "pong") {
          setLastUpdate(message.at ?? new Date().toISOString());
          setStatus("live");
        }
      });

      socket.addEventListener("close", scheduleReconnect);
      socket.addEventListener("error", () => socket?.close());
    };

    api
      .get<{ events: EventRow[]; polled_at: string }>("/api/live?limit=100")
      .then((response) => {
        if (cancelled) return;
        setEvents(response.events);
        setLastUpdate(response.polled_at);
      })
      .catch(console.error)
      .finally(connect);

    return () => {
      cancelled = true;
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      clearPing();
      socket?.close(1000, "unmounted");
    };
  }, []);

  return { events, status, lastUpdate };
}
