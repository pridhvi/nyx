import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "react-router-dom";
import { listSessions, type SessionRecord } from "./api/client";

type SessionContextValue = {
  sessions: SessionRecord[];
  sessionsLoading: boolean;
  sessionsError: string;
  selectedSessionID: string;
  selected?: SessionRecord;
  setSelectedSessionID: (id: string) => void;
  refreshSessions: () => void;
};

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [manualSessionID, setManualSessionID] = useState("");
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions, refetchInterval: 2500 });
  const sessions = sessionsQuery.data ?? [];
  const routeSessionID = location.pathname.match(/^\/sessions\/([^/]+)/)?.[1] ?? "";
  const selectedSessionID = routeSessionID || manualSessionID || (sessions[0]?.session.id ?? "");

  useEffect(() => {
    if (routeSessionID && routeSessionID !== manualSessionID) {
      setManualSessionID(routeSessionID);
    }
  }, [manualSessionID, routeSessionID]);

  const selected = sessions.find((record) => record.session.id === selectedSessionID);
  const value = useMemo(() => ({
    sessions,
    sessionsLoading: sessionsQuery.isLoading,
    sessionsError: sessionsQuery.error instanceof Error ? sessionsQuery.error.message : "",
    selectedSessionID,
    selected,
    setSelectedSessionID: (id: string) => {
      setManualSessionID(id);
      if (id) {
        navigate(`/sessions/${id}`);
      }
    },
    refreshSessions: () => { void sessionsQuery.refetch(); },
  }), [navigate, selected, selectedSessionID, sessions, sessionsQuery]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSessionContext() {
  const value = useContext(SessionContext);
  if (!value) {
    throw new Error("Session context is unavailable");
  }
  return value;
}
