import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 30000,
});

// ========== 项目管理 ==========
export const createProject = (data: {
  name: string;
  customer_name: string;
  waf_device_ip: string;
  waf_device_name?: string;
  description?: string;
}) => api.post('/projects', data);

export const listProjects = () => api.get('/projects');

export const getProject = (id: string) => api.get(`/projects/${id}`);

export const updateProject = (id: string, data: {
  name?: string;
  customer_name?: string;
  waf_device_ip?: string;
  waf_device_name?: string;
  description?: string;
}) => api.put(`/projects/${id}`, data);

export const deleteProject = (id: string) => api.delete(`/projects/${id}`);

export const uploadLog = (id: string, file: File) => {
  const formData = new FormData();
  formData.append('file', file);
  return api.post(`/projects/${id}/upload`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 300000, // 大文件5分钟超时
  });
};

export const setLogPath = (id: string, logFilePath: string) =>
  api.post(`/projects/${id}/set-log-path`, { log_file_path: logFilePath });

// ========== 分析任务 ==========
export const startAnalysis = (projectId: string, logFilePath?: string) =>
  api.post('/analysis/start', { project_id: projectId, log_file_path: logFilePath });

export const getAnalysisStatus = (projectId: string) =>
  api.get(`/analysis/${projectId}/status`);

export const getAnalysisResults = (projectId: string) =>
  api.get(`/analysis/${projectId}/results`);

export const getProposedRules = (projectId: string) =>
  api.get(`/analysis/${projectId}/rules`);

// ========== WAF设备 ==========
export const addWafDevice = (data: {
  name: string;
  vendor: string;
  base_url: string;
  api_token: string;
  verify_ssl?: boolean;
}) => api.post('/waf-devices', data);

export const listWafDevices = () => api.get('/waf-devices');

export const testWafConnection = (deviceId: string) =>
  api.post(`/waf-devices/${deviceId}/test`);

// ========== 报告 ==========
export const generateReport = (projectId: string, format: 'markdown' | 'word' = 'word') =>
  api.post(`/reports/${projectId}/generate`, { format });

export const downloadReport = (projectId: string) =>
  `/api/v1/reports/${projectId}/download`;

export default api;
