import { Table, Button, Select, message, Space, Typography } from 'antd';
import { useEffect, useState } from 'react';
import { listProjects, generateReport, downloadReport } from '../services/api';

interface Project {
  id: string;
  name: string;
  customer_name: string;
  status: string;
}

export default function ReportManager() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [generating, setGenerating] = useState<string | null>(null);

  useEffect(() => {
    listProjects().then(res => setProjects(res.data || [])).catch(() => {});
  }, []);

  const handleGenerate = async (projectId: string, format: 'word' | 'markdown') => {
    setGenerating(projectId);
    try {
      await generateReport(projectId, format);
      message.success('报告生成成功');
      window.open(downloadReport(projectId), '_blank');
    } catch {
      message.error('报告生成失败');
    } finally {
      setGenerating(null);
    }
  };

  const reviewProjects = projects.filter(p => p.status === 'review');

  const columns = [
    { title: '项目名称', dataIndex: 'name' },
    { title: '客户名称', dataIndex: 'customer_name' },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Project) => (
        <Space>
          <Button
            size="small"
            loading={generating === record.id}
            onClick={() => handleGenerate(record.id, 'word')}
          >
            生成Word报告
          </Button>
          <Button
            size="small"
            loading={generating === record.id}
            onClick={() => handleGenerate(record.id, 'markdown')}
          >
            生成Markdown
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Typography.Title level={4}>报告管理</Typography.Title>
      {reviewProjects.length === 0 ? (
        <Typography.Text type="secondary">暂无已完成分析的项目，请先完成日志分析</Typography.Text>
      ) : (
        <Table rowKey="id" dataSource={reviewProjects} columns={columns} pagination={false} />
      )}
    </div>
  );
}
