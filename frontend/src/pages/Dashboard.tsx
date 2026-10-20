import { Card, Col, Row, Statistic, Typography } from 'antd';
import {
  ProjectOutlined,
  ThunderboltOutlined,
  SafetyOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { useEffect, useState } from 'react';
import { listProjects, listWafDevices } from '../services/api';

const { Title } = Typography;

interface Stats {
  projectCount: number;
  wafDeviceCount: number;
  analyzingCount: number;
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    projectCount: 0,
    wafDeviceCount: 0,
    analyzingCount: 0,
  });

  useEffect(() => {
    async function load() {
      try {
        const [projRes, wafRes] = await Promise.all([listProjects(), listWafDevices()]);
        const projects = projRes.data || [];
        setStats({
          projectCount: projects.length,
          wafDeviceCount: wafRes.data?.length || 0,
          analyzingCount: projects.filter((p: any) => p.status === 'analyzing').length,
        });
      } catch {
        // 静默处理
      }
    }
    load();
  }, []);

  return (
    <div>
      <Title level={4}>仪表盘</Title>
      <Row gutter={16}>
        <Col span={6}>
          <Card>
            <Statistic title="项目总数" value={stats.projectCount} prefix={<ProjectOutlined />} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="分析中" value={stats.analyzingCount} prefix={<ThunderboltOutlined />} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="WAF设备" value={stats.wafDeviceCount} prefix={<SafetyOutlined />} />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic title="已生成报告" value={0} prefix={<FileTextOutlined />} />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
