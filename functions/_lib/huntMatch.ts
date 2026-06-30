export interface HuntRuleFilters {
  min_confidence: number;
  trap: string | null;
  protocol: string | null;
  tag: string | null;
  has_credentials: number | null;
}

export interface HuntMatchEvent {
  confidence: number;
  trap: string;
  protocol: string;
  has_username: number;
  has_password: number;
  tags_json: string;
}

function parseTags(tagsJson: string): string[] {
  try {
    const parsed = JSON.parse(tagsJson || "[]");
    return Array.isArray(parsed) ? parsed.filter((tag): tag is string => typeof tag === "string") : [];
  } catch {
    return [];
  }
}

export function eventMatchesHunt(event: HuntMatchEvent, rule: HuntRuleFilters): boolean {
  if (event.confidence < rule.min_confidence) return false;
  if (rule.trap && event.trap !== rule.trap) return false;
  if (rule.protocol && event.protocol !== rule.protocol) return false;
  if (rule.tag) {
    const tags = parseTags(event.tags_json);
    if (!tags.includes(rule.tag)) return false;
  }
  if (rule.has_credentials !== null && rule.has_credentials !== undefined) {
    const hasCredentials = Boolean(event.has_username || event.has_password);
    if (rule.has_credentials === 1 && !hasCredentials) return false;
    if (rule.has_credentials === 0 && hasCredentials) return false;
  }
  return true;
}
