import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './index.css';
// Load the presentation theme last, after route-specific styles.
import './styles/ntk-p08-design-system.css';
import './styles/ntk-p09-monochrome.css';
import './styles/ntk-p10-sharpness.css';
import './styles/ntk-p11-optical-contrast.css';
import './styles/ntk-p12-pipeline-optical.css';
import './styles/ntk-p14-frontend-polish.css';
import './styles/ntk-p15-layout-cleanup.css';

createRoot(document.getElementById('root')).render(
<StrictMode>
    <App />
</StrictMode>
);