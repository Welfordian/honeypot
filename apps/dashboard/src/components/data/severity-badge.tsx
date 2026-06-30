import { Badge } from "@/components/ui/badge";
import { confidenceVariant, severityVariant } from "@/lib/utils";

interface SeverityBadgeProps {
  value: number;
  type?: "severity" | "confidence";
}

export function SeverityBadge({ value, type = "severity" }: SeverityBadgeProps) {
  const variant = type === "confidence" ? confidenceVariant(value) : severityVariant(value);
  return <Badge variant={variant}>{value}</Badge>;
}
