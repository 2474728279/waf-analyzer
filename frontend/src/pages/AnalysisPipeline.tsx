import { Steps, Card, Descriptions, Table, Tag, Spin, Button, message, Progress, Space } from 'antd';
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  getProject, getAnalysisStatus, getAnalysisResults, generateReport, downloadReport,
} from '../services/api';

const stepMap: Record<string, number> = {
  starting: 0, ingest_done: 1, identify_done: 2, analyze_done: 3, generate_done: 4, review: 5,
};

export default function AnalysisPipeline() {
  const [searchParams] = useSearchParams();
  const projectId = searchParams.get('id') || '';
  const [project, setProject] = useState<any>(null);
  const [status, setStatus] = useState<any>(null);
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    if (!projectId) return;
    try {
      const [projRes, statusRes] = await Promise.all([
        getProject(projectId),
        getAnalysisStatus(projectId),
      ]);
      setProject(projRes.data);
      setStatus(statusRes.data);

      if (statusRes.data.status === 'review') {
        const resRes = await getAnalysisResults(projectId);
        setResults(resRes.data);
      }
    } catch {
      message.error('加载数据失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, [projectId]);

  // 轮询分析状态
  useEffect(() => {
    if (!projectId || status?.status !== 'analyzing') return;
    const timer = setInterval(async () => {
      try {
        const res = await getAnalysisStatus(projectId);
        setStatus(res.data);
        if (res.data.status !== 'analyzing') {
          clearInterval(timer);
          loadData();
        }
      } catch { clearInterval(timer); }
    }, 3000);
    return () => clearInterval(timer);
  }, [projectId, status?.status]);

  const handleGenerateReport = async (format: 'word' | 'markdown') => {
    try {
      const res = await generateReport(projectId, format);
      message.success('报告生成成功');
      window.open(downloadReport(projectId), '_blank');
    } catch {
      message.error('报告生成失败');
    }
  };

  if (loading) return <Spin size="large" />;
  if (!projectId) return <div>请从项目列表选择一个项目</div>;

  const currentStep = stepMap[status?.current_step || 'starting'] ?? 0;

  return (
    <div>
      <Steps
        current={currentStep}
        items={[
          { title: '数据摄入' },
          { title: '扫描器识别' },
          { title: '根因分析' },
          { title: '规则生成' },
          { title: '人工审阅' },
        ]}
        style={{ marginBottom: 24 }}
      />

      {/* 分析状态概览 */}
      <Card title="分析状态" style={{ marginBottom: 16 }}>
        <Descriptions column={4}>
          <Descriptions.Item label="日志总量">{status?.total_logs || 0}</Descriptions.Item>
          <Descriptions.Item label="扫描器IP数">{status?.scanner_ip_count || 0}</Descriptions.Item>
          <Descriptions.Item label="建议规则数">{status?.proposed_rules_count || 0}</Descriptions.Item>
          <Descriptions.Item label="当前步骤">{status?.current_step || '-'}</Descriptions.Item>
        </Descriptions>
      </Card>

      {/* 分析结果 */}
      {results && (
        <>
          {/* 攻击类型分布 */}
          <Card title="攻击类型分布" style={{ marginBottom: 16 }}>
            <Table
              size="small"
              pagination={false}
              dataSource={Object.entries(results.attack_type_distribution || {}).map(([k, v], i) => ({
                key: i, type: k, count: v as number,
                pct: results.total_logs ? ((v as number) / results.total_logs * 100).toFixed(1) : '0',
              }))}
              columns={[
                { title: '攻击类型', dataIndex: 'type' },
                { title: '告警数', dataIndex: 'count' },
                { title: '占比(%)', dataIndex: 'pct' },
              ]}
            />
          </Card>

          {/* 根因分析 */}
          <Card title="根因分析" style={{ marginBottom: 16 }}>
            <Table
              size="small"
              pagination={false}
              dataSource={(results.root_causes || []).map((rc: any, i: number) => ({ key: i, ...rc }))}
              columns={[
                { title: '类别', dataIndex: 'category' },
                { title: '告警数', dataIndex: 'log_count' },
                { title: '占比(%)', dataIndex: 'percentage', render: (v: number) => v?.toFixed(1) },
                { title: '描述', dataIndex: 'description' },
              ]}
            />
          </Card>

          {/* 建议规则 */}
          <Card
            title={`建议规则 (${(results.proposed_rules || []).length}条)`}
            style={{ marginBottom: 16 }}
            extra={
              <Space>
                <Button onClick={() => handleGenerateReport('word')}>导出Word报告</Button>
                <Button onClick={() => handleGenerateReport('markdown')}>导出Markdown</Button>
              </Space>
            }
          >
            <Table
              size="small"
              scroll={{ x: 800 }}
              dataSource={(results.proposed_rules || []).map((r: any, i: number) => ({ key: i, ...r }))}
              columns={[
                { title: '序号', render: (_: any, __: any, i: number) => i + 1, width: 60 },
                { title: '规则名称', dataIndex: 'name', ellipsis: true },
                { title: '攻击类型', dataIndex: 'attack_type', width: 100 },
                {
                  title: '关闭模块',
                  dataIndex: 'disabled_modules',
                  width: 200,
                  render: (modules: string[]) =>
                    modules?.map((m: string) => <Tag key={m} color="orange">{m}</Tag>),
                },
                { title: '覆盖告警', dataIndex: 'coverage_count', width: 90 },
                { title: '策略', dataIndex: 'strategy', width: 100 },
                { title: '置信度', dataIndex: 'confidence', width: 80, render: (v: number) => `${(v * 100).toFixed(0)}%` },
              ]}
            />
          </Card>
        </>
      )}
    </div>
  );
}
