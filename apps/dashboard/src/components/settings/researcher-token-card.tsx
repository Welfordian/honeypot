import { useEffect, useState } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  clearResearcherToken,
  getResearcherToken,
  setResearcherToken
} from "@/lib/researcher-token";

export function ResearcherTokenCard() {
  const [token, setToken] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setToken(getResearcherToken() ?? "");
  }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="h-4 w-4 text-primary" />
          Researcher access
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">
          Store a researcher API token for this browser session to download PCAP captures and request
          expanded payload views. The token is kept in sessionStorage and cleared when the tab closes.
          It is only sent as an Authorization header on researcher endpoints.
        </p>
        <Input
          type="password"
          autoComplete="off"
          placeholder="Bearer token"
          value={token}
          onChange={(event) => {
            setToken(event.target.value);
            setSaved(false);
          }}
        />
        <div className="flex flex-wrap gap-2">
          <Button
            size="sm"
            onClick={() => {
              setResearcherToken(token);
              setSaved(true);
            }}
            disabled={!token.trim()}
          >
            Save locally
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              clearResearcherToken();
              setToken("");
              setSaved(false);
            }}
          >
            Clear
          </Button>
          {saved && (
            <span className="text-xs text-muted-foreground self-center">Saved for this browser session.</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
