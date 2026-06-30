import { Bell, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { EmptyState } from "@/components/data/empty-state";
import { ErrorBanner } from "@/components/data/error-banner";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import {
  getHuntAdminToken,
  huntAdminHeaders,
  setHuntAdminToken,
  useHuntRules,
  usePublicHunts,
  useWebhookSubscriptions
} from "@/hooks/use-queries";
import { api } from "@/lib/api";
import type { HuntRule } from "@/types/api";

export function HuntsPage() {
  const queryClient = useQueryClient();
  const [adminToken, setAdminToken] = useState(getHuntAdminToken());
  const [name, setName] = useState("");
  const [minConfidence, setMinConfidence] = useState("70");
  const [trap, setTrap] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [selectedRuleId, setSelectedRuleId] = useState("");
  const [error, setError] = useState<string | null>(null);

  const { data: publicHunts, error: publicHuntsError } = usePublicHunts();
  const { data: huntRules, isLoading, error: loadError } = useHuntRules();
  const { data: webhooks, error: webhooksError } = useWebhookSubscriptions();

  function saveToken() {
    setHuntAdminToken(adminToken.trim());
    void queryClient.invalidateQueries({ queryKey: ["hunt-rules"] });
    void queryClient.invalidateQueries({ queryKey: ["webhook-subscriptions"] });
  }

  async function createHunt() {
    setError(null);
    try {
      await api.post<{ hunt_rule: HuntRule }>(
        "/api/v1/admin/hunts",
        {
          name: name.trim(),
          min_confidence: Number(minConfidence),
          trap: trap.trim() || null,
          enabled: true
        },
        huntAdminHeaders()
      );
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["hunt-rules"] });
      void queryClient.invalidateQueries({ queryKey: ["public-hunts"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create hunt rule.");
    }
  }

  async function addWebhook() {
    if (!selectedRuleId || !webhookUrl.trim()) return;
    setError(null);
    try {
      await api.post(
        "/api/v1/admin/hunts?webhooks=1",
        { hunt_rule_id: selectedRuleId, url: webhookUrl.trim(), enabled: true },
        huntAdminHeaders()
      );
      setWebhookUrl("");
      void queryClient.invalidateQueries({ queryKey: ["webhook-subscriptions"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add webhook.");
    }
  }

  async function deleteWebhook(id: string) {
    setError(null);
    try {
      await api.delete(`/api/v1/admin/hunts?webhooks=1&id=${encodeURIComponent(id)}`, huntAdminHeaders());
      void queryClient.invalidateQueries({ queryKey: ["webhook-subscriptions"] });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete webhook.");
    }
  }

  return (
    <>
      <PageHeader title="Hunts & Webhooks" />
      <div className="flex flex-col gap-4 p-4 sm:p-6">
        {(error || loadError || publicHuntsError || webhooksError) && (
          <ErrorBanner
            message={
              error ??
              (loadError instanceof Error
                ? loadError.message
                : publicHuntsError instanceof Error
                  ? publicHuntsError.message
                  : webhooksError instanceof Error
                    ? webhooksError.message
                    : "Failed to load hunt data.")
            }
          />
        )}

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Indexer admin token</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 sm:flex-row">
            <Input
              aria-label="Indexer admin token"
              type="password"
              placeholder="x-indexer-token value"
              value={adminToken}
              onChange={(e) => setAdminToken(e.target.value)}
            />
            <Button onClick={saveToken}>Save token</Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Active public hunts</CardTitle>
          </CardHeader>
          <CardContent>
            {!publicHunts?.hunts.length ? (
              <EmptyState message="No enabled hunt rules yet." />
            ) : (
              <div className="flex flex-wrap gap-2">
                {publicHunts.hunts.map((hunt) => (
                  <Badge key={hunt.id} variant="outline">
                    {hunt.name} · ≥{hunt.min_confidence}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Plus className="h-4 w-4" />
              Create hunt rule
            </CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
            <Input
              placeholder="Min confidence"
              value={minConfidence}
              onChange={(e) => setMinConfidence(e.target.value)}
            />
            <Input placeholder="Trap (optional)" value={trap} onChange={(e) => setTrap(e.target.value)} />
            <Button onClick={() => void createHunt()} disabled={!name.trim() || !getHuntAdminToken()}>
              Create hunt
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Hunt rules</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Loading hunt rules…</p>
            ) : !huntRules?.hunt_rules.length ? (
              <EmptyState message="Save an indexer admin token to manage hunt rules." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Min conf.</TableHead>
                    <TableHead>Trap</TableHead>
                    <TableHead>Enabled</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {huntRules.hunt_rules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>{rule.name}</TableCell>
                      <TableCell>{rule.min_confidence}</TableCell>
                      <TableCell>{rule.trap || "—"}</TableCell>
                      <TableCell>{rule.enabled ? "Yes" : "No"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Bell className="h-4 w-4" />
              Webhook subscriptions
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <Input
                placeholder="Hunt rule ID"
                value={selectedRuleId}
                onChange={(e) => setSelectedRuleId(e.target.value)}
              />
              <Input
                placeholder="https://hooks.example.com/..."
                value={webhookUrl}
                onChange={(e) => setWebhookUrl(e.target.value)}
              />
              <Button onClick={() => void addWebhook()} disabled={!getHuntAdminToken()}>
                Add webhook
              </Button>
            </div>
            {!webhooks?.webhook_subscriptions.length ? (
              <EmptyState message="No webhooks configured." />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>URL</TableHead>
                    <TableHead>Hunt</TableHead>
                    <TableHead>Last delivery</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {webhooks.webhook_subscriptions.map((hook) => (
                    <TableRow key={hook.id}>
                      <TableCell className="max-w-xs truncate font-mono text-xs">{hook.url}</TableCell>
                      <TableCell className="font-mono text-xs">{hook.hunt_rule_id}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {hook.last_delivered_at || hook.last_error || "—"}
                      </TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => void deleteWebhook(hook.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
