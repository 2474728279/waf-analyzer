import { Table, Button, Modal, Form, Input, Select, Switch, message, Space, Tag } from 'antd';
import { PlusOutlined, ApiOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';
import { listWafDevices, addWafDevice, testWafConnection } from '../services/api';

interface WafDevice {
  id: string;
  name: string;
  vendor: string;
  base_url: string;
  api_token: string;
  verify_ssl: boolean;
}

export default function WafDeviceManager() {
  const [devices, setDevices] = useState<WafDevice[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();
  const [testing, setTesting] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await listWafDevices();
      setDevices(res.data || []);
    } catch {
      message.error('加载WAF设备列表失败');
    }
  };

  useEffect(() => { load(); }, []);

  const handleAdd = async (values: any) => {
    try {
      await addWafDevice(values);
      message.success('WAF设备添加成功');
      setModalOpen(false);
      form.resetFields();
      load();
    } catch {
      message.error('添加WAF设备失败');
    }
  };

  const handleTest = async (deviceId: string) => {
    setTesting(deviceId);
    try {
      const res = await testWafConnection(deviceId);
      if (res.data.connected) {
        message.success('连接测试成功');
      } else {
        message.error(`连接失败: ${res.data.error || '未知错误'}`);
      }
    } catch {
      message.error('连接测试异常');
    } finally {
      setTesting(null);
    }
  };

  const columns = [
    { title: '设备名称', dataIndex: 'name', key: 'name' },
    {
      title: '类型',
      dataIndex: 'vendor',
      key: 'vendor',
      render: (v: string) => <Tag color="blue">{v}</Tag>,
    },
    { title: 'API地址', dataIndex: 'base_url', key: 'base_url' },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: WafDevice) => (
        <Button
          size="small"
          icon={<ApiOutlined />}
          loading={testing === record.id}
          onClick={() => handleTest(record.id)}
        >
          测试连接
        </Button>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h3>WAF设备管理</h3>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalOpen(true)}>
          添加设备
        </Button>
      </div>

      <Table rowKey="id" dataSource={devices} columns={columns} pagination={false} />

      <Modal
        title="添加WAF设备"
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
      >
        <Form form={form} layout="vertical" onFinish={handleAdd}>
          <Form.Item name="name" label="设备名称" rules={[{ required: true }]}>
            <Input placeholder="例：生产环境SafeLine" />
          </Form.Item>
          <Form.Item name="vendor" label="WAF类型" initialValue="safeline">
            <Select options={[
              { value: 'safeline', label: '雷池 SafeLine' },
              { value: 'modsecurity', label: 'ModSecurity' },
            ]} />
          </Form.Item>
          <Form.Item name="base_url" label="API地址" rules={[{ required: true }]}>
            <Input placeholder="例：https://10.1.233.98:9443" />
          </Form.Item>
          <Form.Item name="api_token" label="API Token" rules={[{ required: true }]}>
            <Input.Password placeholder="SafeLine API-TOKEN" />
          </Form.Item>
          <Form.Item name="verify_ssl" label="验证SSL" valuePropName="checked" initialValue={false}>
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
