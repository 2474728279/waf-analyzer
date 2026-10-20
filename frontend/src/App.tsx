import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import AppLayout from './components/AppLayout';
import Dashboard from './pages/Dashboard';
import ProjectList from './pages/ProjectList';
import AnalysisPipeline from './pages/AnalysisPipeline';
import WafDeviceManager from './pages/WafDeviceManager';
import ReportManager from './pages/ReportManager';

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <BrowserRouter>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/projects" element={<ProjectList />} />
            <Route path="/analysis" element={<AnalysisPipeline />} />
            <Route path="/waf" element={<WafDeviceManager />} />
            <Route path="/reports" element={<ReportManager />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ConfigProvider>
  );
}

export default App;
