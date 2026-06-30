import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import type { DimensionCount } from "@/types/api";

interface BarChartPanelProps {
  title: string;
  data: Array<{ key: string | number; count: number }>;
  height?: number;
}

export function BarChartPanel({ title, data, height = 220 }: BarChartPanelProps) {
  const chartData = data.map((row) => ({
    name: String(row.key),
    count: row.count
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
            <BarChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(30,46,40,0.8)" />
              <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="#6b7f76" />
              <YAxis tick={{ fontSize: 11 }} stroke="#6b7f76" allowDecimals={false} />
              <Tooltip
                cursor={{ fill: "transparent" }}
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
              <Bar
                dataKey="count"
                fill="#00e676"
                radius={[4, 4, 0, 0]}
                activeBar={{ fill: "#00e676", opacity: 0.85 }}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}

export type { DimensionCount };
