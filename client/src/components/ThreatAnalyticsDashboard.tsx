import { useEffect, useState } from 'react';
import { trpc } from '@/lib/trpc';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { LineChart, Line, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { AlertTriangle, TrendingUp, Shield, Activity } from 'lucide-react';

interface ThreatAnalyticsDashboardProps {
  days?: number;
}

export function ThreatAnalyticsDashboard({ days = 7 }: ThreatAnalyticsDashboardProps) {
  const [selectedPeriod, setSelectedPeriod] = useState<'hourly' | 'daily' | 'weekly' | 'monthly'>('daily');

  // 脅威サマリーを取得
  const summaryQuery = trpc.threatAnalytics.getSummary.useQuery({ days });

  // 攻撃タイプ分布を取得
  const attackTypeQuery = trpc.threatAnalytics.getAttackTypeDistribution.useQuery({ days });

  // 攻撃元国分布を取得
  const countryDistributionQuery = trpc.threatAnalytics.getSourceCountryDistribution.useQuery({ days, limit: 10 });

  // 時系列データを取得
  const timeSeriesQuery = trpc.threatAnalytics.getThreatTimeSeries.useQuery({
    days,
    granularity: selectedPeriod === 'hourly' ? 'hourly' : 'daily',
  });

  // 分析データを取得
  const analyticsQuery = trpc.threatAnalytics.getAnalyticsByPeriod.useQuery({
    period: selectedPeriod,
    limit: 30,
  });

  const summary = summaryQuery.data?.data;
  const attackTypes = attackTypeQuery.data?.data || [];
  const countries = countryDistributionQuery.data?.data || [];
  const timeSeries = timeSeriesQuery.data?.data || [];

  // 深刻度の色定義
  const severityColors: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280',
  };

  return (
    <div className="space-y-6">
      {/* サマリーカード */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Total Threats
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{summary?.totalThreats || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Last {days} days</p>
          </CardContent>
        </Card>

        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-orange-400" />
              Critical
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-400">{summary?.criticalCount || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Highest severity</p>
          </CardContent>
        </Card>

        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-yellow-400" />
              High
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-orange-400">{summary?.highCount || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">High severity</p>
          </CardContent>
        </Card>

        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Attackers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-blue-400">{summary?.uniqueAttackers || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Unique sources</p>
          </CardContent>
        </Card>
      </div>

      {/* 時系列チャート */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">Threat Timeline</CardTitle>
            <div className="flex gap-2">
              {(['hourly', 'daily', 'weekly', 'monthly'] as const).map((period) => (
                <button
                  key={period}
                  onClick={() => setSelectedPeriod(period)}
                  className={`px-3 py-1 text-xs rounded-md transition-colors ${
                    selectedPeriod === period
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted text-muted-foreground hover:bg-muted/80'
                  }`}
                >
                  {period.charAt(0).toUpperCase() + period.slice(1)}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {timeSeries.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={timeSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="timestamp" stroke="#666" />
                <YAxis stroke="#666" />
                <Tooltip contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }} />
                <Legend />
                <Line type="monotone" dataKey="critical" stroke={severityColors.critical} strokeWidth={2} />
                <Line type="monotone" dataKey="high" stroke={severityColors.high} strokeWidth={2} />
                <Line type="monotone" dataKey="medium" stroke={severityColors.medium} strokeWidth={2} />
                <Line type="monotone" dataKey="low" stroke={severityColors.low} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-80 flex items-center justify-center text-muted-foreground">
              No data available
            </div>
          )}
        </CardContent>
      </Card>

      {/* 攻撃タイプ分布 と 攻撃元国分布 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* 攻撃タイプ分布 */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Attack Type Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {attackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={attackTypes}
                    dataKey="count"
                    nameKey="type"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label
                  >
                    {attackTypes.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={Object.values(severityColors)[index % Object.values(severityColors).length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-80 flex items-center justify-center text-muted-foreground">
                No data available
              </div>
            )}
          </CardContent>
        </Card>

        {/* 攻撃元国分布 */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Top Source Countries</CardTitle>
          </CardHeader>
          <CardContent>
            {countries.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={countries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="country" stroke="#666" angle={-45} textAnchor="end" height={80} />
                  <YAxis stroke="#666" />
                  <Tooltip contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }} />
                  <Bar dataKey="count" fill="#3b82f6" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-80 flex items-center justify-center text-muted-foreground">
                No data available
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 攻撃タイプ詳細リスト */}
      <Card className="border-border/50 bg-card/80">
        <CardHeader>
          <CardTitle className="text-sm font-medium">Attack Type Details</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {attackTypes.length > 0 ? (
              attackTypes.map((type) => (
                <div key={type.type} className="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                  <span className="text-sm font-medium">{type.type}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-xs">
                      {type.count}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{type.percentage}%</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center text-muted-foreground text-sm">No data available</div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
