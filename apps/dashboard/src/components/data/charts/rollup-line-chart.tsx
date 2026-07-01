import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { formatChartValue, formatCount } from "@/lib/format";
import { formatTime } from "@/lib/utils";
import type { RollupSeries } from "@/types/api";

const SERIES_COLORS = ["#00e676", "#40c4ff", "#ffab40", "#ea80fc", "#ff5252", "#ffd740", "#69f0ae", "#b388ff"];

interface RollupLineChartProps {
  title: string;
  series: RollupSeries[];
  maxSeries?: number;
  height?: number;
}

export function RollupLineChart({ title, series, maxSeries = 6, height = 260 }: RollupLineChartProps) {
  const ranked = [...series]
    .map((item) => ({
      ...item,
      total: item.points.reduce((sum, point) => sum + point.count, 0)
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, maxSeries);

  const bucketSet = new Set<string>();
  for (const item of ranked) {
    for (const point of item.points) bucketSet.add(point.bucket);
  }
  const buckets = [...bucketSet].sort();

  const countsByKey = new Map(
    ranked.map((item) => [
      item.key,
      new Map(item.points.map((point) => [point.bucket, point.count]))
    ])
  );

  const chartData = buckets.map((bucket) => {
    const row: Record<string, string | number> = {
      bucket,
      label: formatTime(bucket)
    };
    for (const item of ranked) {
      row[item.key] = countsByKey.get(item.key)?.get(bucket) ?? 0;
    }
    return row;
  });

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>
      <div className="p-4" style={{ height }}>
        {chartData.length === 0 || ranked.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No trend data</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,46,40,0.8)" />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} stroke="#6b7f76" />
              <YAxis
                tick={{ fontSize: 11 }}
                stroke="#6b7f76"
                allowDecimals={false}
                tickFormatter={formatCount}
              />
              <Tooltip
                contentStyle={{
                  background: "#0f1513",
                  border: "1px solid #1e2e28",
                  borderRadius: 8,
                  fontSize: 12,
                  color: "#e8f0ec"
                }}
                labelStyle={{ color: "#e8f0ec" }}
                itemStyle={{ color: "#e8f0ec" }}
                formatter={(value) => formatChartValue(value as number | string)}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              {ranked.map((item, index) => (
                <Line
                  key={item.key}
                  type="monotone"
                  dataKey={item.key}
                  stroke={SERIES_COLORS[index % SERIES_COLORS.length]}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
