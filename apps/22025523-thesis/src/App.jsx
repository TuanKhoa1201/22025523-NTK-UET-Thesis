import {HashRouter, Navigate, Route, Routes} from 'react-router-dom';
import './App.css';
import './styles/polish.css';
import './styles/typography.css';
import './styles/revision.css';
import './styles/analysis-revision.css';
import './styles/targeted-fixes.css';
import './styles/scene3d.css';
import './styles/scanner-resilience.css';
import './styles/ntk-final.css';
import './styles/production-readiness.css';
import './styles/ntk-p05.css';
import './styles/ntk-p06.css';
import AppShell from './components/layout/AppShell';
import ErrorBoundary from './components/common/ErrorBoundary';
import Overview from './pages/Overview';
import Scanner from './pages/Scanner';
import StatusPage from './pages/StatusPage';
import {FindingDetail, Results} from './pages/Results';
import {About} from './pages/UtilityPages';
import ReportsPage from './pages/ReportsPage';
import ReviewPage from './pages/ReviewPage';
import History from './pages/HistoryPage';

function ScannerRoute() {
  return (
    <ErrorBoundary fallback={(retry) => (
      <section className="card" role="alert">
        <h2>Không thể mở khu vực phân tích</h2>
        <p>Thanh điều hướng vẫn hoạt động. Vui lòng thử tải lại trang phân tích.</p>
        <button type="button" className="button-secondary" onClick={retry}>Thử lại</button>
      </section>
    )}>
      <Scanner />
    </ErrorBoundary>
  );
}

function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<Overview />} />
          <Route path="/scanner" element={<ScannerRoute />} />
          <Route path="/history" element={<History />} />
          <Route path="/results" element={<Results />} />
          <Route path="/finding/:id" element={<FindingDetail />} />
          <Route path="/findings" element={<Results />} />
          <Route path="/review" element={<ReviewPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}

export default App;
