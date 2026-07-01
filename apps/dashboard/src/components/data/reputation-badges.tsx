import { Badge } from "@/components/ui/badge";
import { formatCount } from "@/lib/format";
import type { GreynoiseReputation } from "@/types/api";

function greynoiseVariant(classification: string | null | undefined): "critical" | "secondary" | "outline" | "low" {
  switch (classification?.toLowerCase()) {
    case "malicious":
      return "critical";
    case "benign":
      return "secondary";
    case "unknown":
      return "outline";
    default:
      return "low";
  }
}

interface ReputationBadgesProps {
  greynoise?: GreynoiseReputation | null;
}

export function ReputationBadges({ greynoise }: ReputationBadgesProps) {
  if (!greynoise) return null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      {greynoise.classification && (
        <Badge variant={greynoiseVariant(greynoise.classification)}>
          GreyNoise: {greynoise.classification}
        </Badge>
      )}
      {greynoise.name && <Badge variant="outline">{greynoise.name}</Badge>}
      {greynoise.tags.map((tag) => (
        <Badge key={tag} variant="outline">
          {tag}
        </Badge>
      ))}
    </div>
  );
}

interface VirusTotalRatioProps {
  stats?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  } | null;
}

export function VirusTotalRatio({ stats }: VirusTotalRatioProps) {
  if (!stats) return null;

  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  if (total === 0) return null;

  const flagged = stats.malicious + stats.suspicious;
  const variant = stats.malicious > 0 ? "critical" : stats.suspicious > 0 ? "high" : "secondary";

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={variant}>
          VirusTotal: {formatCount(flagged)}/{formatCount(total)} flagged
        </Badge>
        <span className="text-xs text-muted-foreground">
          {formatCount(stats.malicious)} malicious · {formatCount(stats.suspicious)} suspicious ·{" "}
          {formatCount(stats.harmless)} harmless · {formatCount(stats.undetected)} undetected
        </span>
      </div>
    </div>
  );
}
