import { useCallback, useEffect, useRef, useState } from "react";

export function useInfiniteLoader(
  hasMore: boolean,
  loading: boolean,
  onLoadMore: () => void
) {
  const [node, setNode] = useState<HTMLDivElement | null>(null);
  const hasMoreRef = useRef(hasMore);
  const loadingRef = useRef(loading);
  const onLoadMoreRef = useRef(onLoadMore);
  const triggeredForCurrentEntryRef = useRef(false);

  useEffect(() => {
    hasMoreRef.current = hasMore;
    loadingRef.current = loading;
    onLoadMoreRef.current = onLoadMore;
    if (!hasMore) triggeredForCurrentEntryRef.current = false;
  }, [hasMore, loading, onLoadMore]);

  useEffect(() => {
    if (!node) return;

    const observer = new IntersectionObserver(
      (entries) => {
        const isIntersecting = entries.some((entry) => entry.isIntersecting);
        if (!isIntersecting) {
          triggeredForCurrentEntryRef.current = false;
          return;
        }

        if (
          hasMoreRef.current &&
          !loadingRef.current &&
          !triggeredForCurrentEntryRef.current
        ) {
          triggeredForCurrentEntryRef.current = true;
          onLoadMoreRef.current();
        }
      },
      { rootMargin: "360px 0px" }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [node]);

  return useCallback((element: HTMLDivElement | null) => {
    setNode(element);
  }, []);
}
