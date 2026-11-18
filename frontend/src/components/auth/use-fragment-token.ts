"use client";

import { useEffect, useRef, useState } from "react";

/**
 * Reads `#token=...` from the URL once, then strips it from the address bar
 * and history. Email links put tokens in the fragment so they never reach
 * server logs or Referer headers; removing it also keeps the token out of
 * browser history and screenshots.
 *
 * The ref survives StrictMode's double effect run, which would otherwise read
 * the already-stripped hash the second time and lose the token.
 */
export function useFragmentToken() {
  const captured = useRef<string | null | undefined>(undefined);
  const [state, setState] = useState<{ ready: boolean; token: string | null }>({ ready: false, token: null });
  useEffect(() => {
    if (captured.current === undefined) {
      const raw = new URLSearchParams(window.location.hash.slice(1)).get("token");
      captured.current = raw && raw.length >= 10 && raw.length <= 128 ? raw : null;
      if (window.location.hash) {
        window.history.replaceState(null, "", window.location.pathname + window.location.search);
      }
    }
    setState({ ready: true, token: captured.current });
  }, []);
  return state;
}
