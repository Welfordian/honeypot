import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { formatTime } from "@/lib/utils";

interface TimelineChartProps {
  title: string;
  data: Array<{ bucket: string; count: number; unique_ips?: number }>;
  height?: number;
}

export function TimelineChart({ title, data, height = 240 }: TimelineChartProps) {
  const chartData = data.map((point) => ({
    ...point,
    label: formatTime(point.bucket)
  }));

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
      </div>
      <div className="p-4" style={{ height }}>
        {chartData.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No data</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="timelineFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00e676" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#00e676" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,46,40,0.8)" />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} stroke="#6b7f76" />
              <YAxis tick={{ fontSize: 11 }} stroke="#6b7f76" allowDecimals={false} />
              <Tooltip
                cursor={{ fill: "rgba(30, 46, 40, 0.25)" }}
                contentStyle={{
                  background: "#0f1513",
                  border: "1px solid #1e2e28",
                  borderRadius: 8,
                  fontSize: 12,
                  color: "#e8f0ec"
                }}
                labelStyle={{ color: "#e8f0ec" }}
                itemStyle={{ color: "#e8f0ec" }}
              />
              <Area type="monotone" dataKey="count" stroke="#00e676" fill="url(#timelineFill)" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
