import { Layout, Menu, Typography } from 'antd';
import {
  DashboardOutlined,
  ProjectOutlined,
  ThunderboltOutlined,
  SafetyOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';

const { Header, Sider, Content } = Layout;
const { Title } = Typography;

const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '仪表盘' },
  { key: '/projects', icon: <ProjectOutlined />, label: '项目管理' },
  { key: '/analysis', icon: <ThunderboltOutlined />, label: '分析流水线' },
  { key: '/waf', icon: <SafetyOutlined />, label: 'WAF设备' },
  { key: '/reports', icon: <FileTextOutlined />, label: '报告管理' },
];

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider width={200} theme="dark">
        <div style={{ padding: '16px', textAlign: 'center' }}>
          <Title level={4} style={{ color: '#fff', margin: 0 }}>
            WAF日志分析
          </Title>
          <Typography.Text style={{ color: '#999', fontSize: 12 }}>
            智能体平台
          </Typography.Text>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header style={{ background: '#fff', padding: '0 24px', borderBottom: '1px solid #f0f0f0' }}>
          <Title level={4} style={{ margin: '14px 0' }}>
            WAF日志分析智能体平台
          </Title>
        </Header>
        <Content style={{ margin: 24, padding: 24, background: '#fff', borderRadius: 8, minHeight: 360 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
}
