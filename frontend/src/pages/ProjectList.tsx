import {
  Table, Button, Modal, Form, Input, Space, Upload, message, Tag, Popconfirm, Spin, Progress,
} from 'antd';
import { PlusOutlined, UploadOutlined, ThunderboltOutlined, EditOutlined, DeleteOutlined, LoadingOutlined, FolderOpenOutlined } from '@ant-design/icons';
import { useEffect, useState } from 'react';
import { listProjects, createProject, updateProject, deleteProject, uploadLog, setLogPath, startAnalysis, getAnalysisStatus } from '../services/api';

interface Project {
  id: string;
  name: string;
  customer_name: string;
  waf_device_ip: string;
  waf_device_name: string;
  description: string;
  status: string;
  total_logs: number;
  log_file_path: string | null;
}

const statusMap: Record<string, { color: string; text: string }> = {
  created: { color: 'default', text: '已创建' },
  uploaded: { color: 'blue', text: '已上传' },
  analyzing: { color: 'processing', text: '分析中' },
  review: { color: 'success', text: '待审阅' },
  failed: { color: 'error', text: '分析失败' },
};

const stepLabel: Record<string, string> = {
  starting: '初始化',
  ingest_done: '数据摄入完成',
  identify_done: '扫描器识别完成',
  analyze_done: '根因分析完成',
  generate_done: '规则生成完成',
};

export default function ProjectList() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [form] = Form.useForm();
  const [pollingIds, setPollingIds] = useState<Set<string>>(new Set());
  const [uploadingId, setUploadingId] = useState<string | null>(null);
  const [analysisSteps, setAnalysisSteps] = useState<Record<string, string>>({});
  const [pathModalOpen, setPathModalOpen] = useState(false);
  const [pathProjectId, setPathProjectId] = useState<string>('');
  const [pathForm] = Form.useForm();

  const load = async () => {
    try {
      const res = await listProjects();
      setProjects(res.data || []);
    } catch {
      message.error('加载项目列表失败');
    }
  };

  useEffect(() => { load(); }, []);

  // 轮询分析状态
  useEffect(() => {
    if (pollingIds.size === 0) return;
    const timer = setInterval(async () => {
      const newPolling = new Set(pollingIds);
      const newSteps = { ...analysisSteps };
      let changed = false;
      for (const pid of pollingIds) {
        try {
          const res = await getAnalysisStatus(pid);
          const step = res.data.current_step || '';
          if (step !== newSteps[pid]) {
            newSteps[pid] = step;
            changed = true;
          }
          if (res.data.status !== 'analyzing') {
            newPolling.delete(pid);
            delete newSteps[pid];
          }
        } catch {
          newPolling.delete(pid);
          delete newSteps[pid];
        }
      }
      if (changed) setAnalysisSteps(newSteps);
      setPollingIds(newPolling);
      if (newPolling.size !== pollingIds.size || changed) load();
    }, 2000);
    return () => clearInterval(timer);
  }, [pollingIds, analysisSteps]);

  const openCreateModal = () => {
    setEditingProject(null);
    form.resetFields();
    setModalOpen(true);
  };

  const openEditModal = (record: Project) => {
    setEditingProject(record);
    form.setFieldsValue({
      name: record.name,
      customer_name: record.customer_name,
      waf_device_ip: record.waf_device_ip,
      waf_device_name: record.waf_device_name,
      description: record.description,
    });
    setModalOpen(true);
  };

  const handleSubmit = async (values: any) => {
    try {
      if (editingProject) {
        await updateProject(editingProject.id, values);
        message.success('项目更新成功');
      } else {
        await createProject(values);
        message.success('项目创建成功');
      }
      setModalOpen(false);
      form.resetFields();
      setEditingProject(null);
      load();
    } catch {
      message.error(editingProject ? '更新项目失败' : '创建项目失败');
    }
  };

  const handleDelete = async (projectId: string) => {
    try {
      await deleteProject(projectId);
      message.success('项目已删除');
      load();
    } catch {
      message.error('删除项目失败');
    }
  };

  const handleUpload = async (projectId: string, file: File) => {
    setUploadingId(projectId);
    const hide = message.loading('正在上传日志文件...', 0);
    try {
      await uploadLog(projectId, file);
      hide();
      message.success('日志上传成功');
      load();
    } catch {
      hide();
      message.error('上传失败');
    } finally {
      setUploadingId(null);
    }
  };

  const handleSetLogPath = async (values: any) => {
    try {
      await setLogPath(pathProjectId, values.logFilePath);
      message.success('日志路径设置成功');
      setPathModalOpen(false);
      pathForm.resetFields();
      load();
    } catch (e: any) {
      message.error(e.response?.data?.detail || '路径设置失败');
    }
  };

  const handleStartAnalysis = async (projectId: string) => {
    try {
      await startAnalysis(projectId);
      message.info('分析已启动，请稍候...');
      setPollingIds(prev => new Set(prev).add(projectId));
      setAnalysisSteps(prev => ({ ...prev, [projectId]: 'starting' }));
      load();
    } catch (e: any) {
      message.error(e.response?.data?.detail || '启动分析失败');
    }
  };

  const getAnalysisProgress = (currentStep: string) => {
    const steps = ['starting', 'ingest_done', 'identify_done', 'analyze_done', 'generate_done'];
    const idx = steps.indexOf(currentStep);
    if (idx < 0) return 0;
    return Math.round(((idx + 1) / steps.length) * 100);
  };

  const columns = [
    { title: '项目名称', dataIndex: 'name', key: 'name' },
    { title: '客户名称', dataIndex: 'customer_name', key: 'customer_name' },
    { title: 'WAF设备IP', dataIndex: 'waf_device_ip', key: 'waf_device_ip' },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string, record: Project) => {
        const s = statusMap[status] || { color: 'default', text: status };
        const step = analysisSteps[record.id];
        if (status === 'analyzing' && step) {
          const pct = getAnalysisProgress(step);
          const label = stepLabel[step] || step;
          return (
            <Space direction="vertical" size={0} style={{ width: 140 }}>
              <Tag color="processing" icon={<LoadingOutlined spin />}>{s.text}</Tag>
              <Progress percent={pct} size="small" status="active" />
              <span style={{ fontSize: 11, color: '#888' }}>{label}</span>
            </Space>
          );
        }
        return <Tag color={s.color}>{s.text}</Tag>;
      },
    },
    { title: '日志数', dataIndex: 'total_logs', key: 'total_logs' },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Project) => (
        <Space wrap>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEditModal(record)}>
            编辑
          </Button>
          {record.status === 'created' && (
            <Upload
              customRequest={({ file, onSuccess, onError }) => {
                handleUpload(record.id, file as File)
                  .then(() => onSuccess?.(null))
                  .catch(() => onError?.(new Error('上传失败')));
              }}
              showUploadList={false}
              accept=".json,.csv,.pkl,.log,.txt"
            >
              <Button size="small" icon={<UploadOutlined />} loading={uploadingId === record.id}>
                {uploadingId === record.id ? '上传中...' : '上传日志'}
              </Button>
            </Upload>
          )}
          {record.status === 'created' && (
            <Button size="small" icon={<FolderOpenOutlined />} onClick={() => {
              setPathProjectId(record.id);
              pathForm.resetFields();
              setPathModalOpen(true);
            }}>
              指定路径
            </Button>
          )}
          {record.status === 'uploaded' && (
            <Popconfirm title="确认启动分析？" onConfirm={() => handleStartAnalysis(record.id)}>
              <Button size="small" type="primary" icon={<ThunderboltOutlined />}>启动分析</Button>
            </Popconfirm>
          )}
          {record.status === 'review' && (
            <Button size="small" type="link" href={`/analysis?id=${record.id}`}>
              查看结果
            </Button>
          )}
          <Popconfirm title="确认删除该项目？" onConfirm={() => handleDelete(record.id)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
        <h3>项目管理</h3>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreateModal}>
          新建项目
        </Button>
      </div>

      <Table
        rowKey="id"
        dataSource={projects}
        columns={columns}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title={editingProject ? '编辑项目' : '新建项目'}
        open={modalOpen}
        onCancel={() => { setModalOpen(false); setEditingProject(null); }}
        onOk={() => form.submit()}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="项目名称" rules={[{ required: true }]}>
            <Input placeholder="例：新华人寿WAF日志分析" />
          </Form.Item>
          <Form.Item name="customer_name" label="客户名称" rules={[{ required: true }]}>
            <Input placeholder="例：新华人寿保险股份有限公司" />
          </Form.Item>
          <Form.Item name="waf_device_ip" label="WAF设备IP" rules={[{ required: true }]}>
            <Input placeholder="例：10.1.233.98" />
          </Form.Item>
          <Form.Item name="waf_device_name" label="WAF设备名称">
            <Input placeholder="例：雷池SafeLine" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="指定日志文件路径"
        open={pathModalOpen}
        onCancel={() => setPathModalOpen(false)}
        onOk={() => pathForm.submit()}
      >
        <Form form={pathForm} layout="vertical" onFinish={handleSetLogPath}>
          <Form.Item name="logFilePath" label="服务器本地路径" rules={[{ required: true }]}>
            <Input placeholder="例：/Users/xxx/data/detect_log.json" />
          </Form.Item>
        </Form>
        <p style={{ color: '#888', fontSize: 12 }}>
          适用于大文件场景（如10GB+的日志文件），直接指定服务器上的文件路径，无需上传。
        </p>
      </Modal>
    </div>
  );
}
