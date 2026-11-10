
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  Clock,
  Database,
  Download,
  FileText,
  Globe,
  History,
  LayoutDashboard,
  Mail,
  MessageSquare,
  Search,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { downloadReportPdf, fetchDashboardStats, fetchScanHistory, submitScan } from "./services/api";
import "./App.css";

const navigation = [
  { name: "Dashboard", icon: LayoutDashboard },
  { name: "Email Scanner", icon: Mail },
  { name: "Website Scanner", icon: Globe },
  { name: "SMS Scanner", icon: MessageSquare },
  { name: "Scan History", icon: History },
  { name: "Reports", icon: FileText },
  { name: "Threat Intelligence", icon: Server },
  { name: "Settings", icon: Settings },
];

const defaultStats = {
  total_scans: 0,
  safe_detections: 0,
  suspicious_detections: 0,
  phishing_detections: 0,
  average_risk_score: 0,
  detection_rate: 0,
};

function App() {
  const [activePage, setActivePage] = useState("Dashboard");
  const [stats, setStats] = useState(defaultStats);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [emailForm, setEmailForm] = useState({ email_text: "", email_headers: "", sender_id: "" });
  const [websiteForm, setWebsiteForm] = useState({ url: "" });
  const [smsForm, setSmsForm] = useState({ message: "", sender_id: "", extracted_url: "" });
  const [scanResults, setScanResults] = useState({});

  const loadDashboard = async () => {
    try {
      const statsData = await fetchDashboardStats();
      const historyData = await fetchScanHistory(1, 8);
      setStats(statsData);
      setHistory(historyData.items || []);
    } catch (err) {
      setError(err.message || "Unable to load dashboard data.");
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  const activityChart = useMemo(() => {
    const fallback = [
      { day: "Mon", scans: 6 },
      { day: "Tue", scans: 9 },
      { day: "Wed", scans: 11 },
      { day: "Thu", scans: 14 },
      { day: "Fri", scans: 17 },
      { day: "Sat", scans: 13 },
      { day: "Sun", scans: 16 },
    ];

    if (!history.length) return fallback;

    return history.slice(0, 7).map((scan, index) => ({
      day: new Date(scan.created_at).toLocaleDateString("en-US", { weekday: "short" }),
      scans: Math.max(4, Math.round((scan.risk_score || 0) / 8) + index),
    })).reverse();
  }, [history]);

  const riskScoreClass = (score) => {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "warning";
    return "safe";
  };

  const runScan = async (scannerType, payload) => {
    setLoading(true);
    setError("");
    try {
      const result = await submitScan(scannerType, payload);
      setScanResults((prev) => ({ ...prev, [scannerType]: result }));
      await loadDashboard();
      return result;
    } catch (err) {
      setError(err.message || "Scan failed.");
      return null;
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (scanId) => {
    try {
      await downloadReportPdf(scanId);
    } catch (err) {
      setError(err.message || "Unable to download PDF.");
    }
  };

  const renderDashboard = () => (
    <div className="dashboard-view">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
          <h1>Dashboard Overview</h1>
          <p>Monitor phishing and smishing threats across the protected environment.</p>
        </div>
        <div className="live-indicator">
          <span className="status-dot"></span>
          Detection Engine Online
        </div>
      </div>

      <div className="stats-grid">
        <StatCard title="Total Scans" value={stats.total_scans} color="blue" icon={Activity} change="Live" />
        <StatCard title="Safe Detections" value={stats.safe_detections} color="green" icon={Shield} change="Verified" />
        <StatCard title="Suspicious Detections" value={stats.suspicious_detections} color="amber" icon={AlertTriangle} change="Watchlist" />
        <StatCard title="Phishing Detections" value={stats.phishing_detections} color="red" icon={ShieldAlert} change="Escalated" />
      </div>

      <div className="quick-scan-grid">
        <QuickScanCard title="Email Scanner" description="Review suspicious emails, headers, and trust signals." icon={Mail} onClick={() => setActivePage("Email Scanner")} />
        <QuickScanCard title="Website Scanner" description="Analyze URLs, redirects, SSL posture, and spoofed domains." icon={Globe} onClick={() => setActivePage("Website Scanner")} />
        <QuickScanCard title="SMS Scanner" description="Detect financial phishing, smishing urge patterns, and link abuse." icon={MessageSquare} onClick={() => setActivePage("SMS Scanner")} />
      </div>

      <div className="content-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3>Scan Activity</h3>
              <p>Threat monitoring trends by day</p>
            </div>
            <span className="period">Last 7 days</span>
          </div>

          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={activityChart}>
                <defs>
                  <linearGradient id="scan-fill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#5eead4" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#5eead4" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1f2d3d" vertical={false} />
                <XAxis dataKey="day" tickLine={false} axisLine={false} stroke="#94a3b8" />
                <YAxis tickLine={false} axisLine={false} stroke="#94a3b8" />
                <Tooltip
                  contentStyle={{
                    background: "#0b1220",
                    border: "1px solid #223246",
                    borderRadius: "10px",
                    color: "#e2e8f0",
                  }}
                />
                <Area type="monotone" dataKey="scans" stroke="#5eead4" strokeWidth={2} fill="url(#scan-fill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h3>Detection Summary</h3>
              <p>Risk posture across recent results</p>
            </div>
          </div>

          <div className="summary-metric">
            <div className="metric-icon danger"><ShieldAlert size={22} /></div>
            <div>
              <strong>{stats.average_risk_score.toFixed(1)}/100</strong>
              <span>Average risk score</span>
            </div>
          </div>

          <div className="summary-metric">
            <div className="metric-icon success"><CheckCircle2 size={22} /></div>
            <div>
              <strong>{stats.detection_rate.toFixed(1)}%</strong>
              <span>High-risk detection rate</span>
            </div>
          </div>

          <div className="summary-meter">
            <div className="meter-fill" style={{ width: `${Math.min(100, stats.detection_rate)}%` }} />
          </div>
        </section>
      </div>

      <section className="panel recent-panel">
        <div className="panel-heading">
          <div>
            <h3>Recent Scan Activity</h3>
            <p>Latest analysis records and findings</p>
          </div>
          <button className="link-button" onClick={() => setActivePage("Scan History")}>View all</button>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Scan</th>
                <th>Type</th>
                <th>Risk</th>
                <th>Classification</th>
                <th>Time</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {history.length ? history.map((item) => (
                <tr key={item.scan_id}>
                  <td>{item.summary || item.scanner_type}</td>
                  <td>{item.scanner_type}</td>
                  <td><span className={`risk-pill ${riskScoreClass(item.risk_score)}`}>{Math.round(item.risk_score)}</span></td>
                  <td>{item.threat_level}</td>
                  <td>{new Date(item.created_at).toLocaleString()}</td>
                  <td><button className="tiny-button" onClick={() => handleDownload(item.scan_id)}>Download</button></td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" className="empty-state">No scans yet. Run a scan to populate the dashboard.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );

  const renderScanner = (type, config) => (
    <div className="scanner-layout">
      <section className="panel scanner-panel">
        <div className="panel-heading">
          <div>
            <h3>{config.title}</h3>
            <p>{config.caption}</p>
          </div>
        </div>

        {type === "email" && (
          <div className="input-stack">
            <textarea value={emailForm.email_text} onChange={(e) => setEmailForm({ ...emailForm, email_text: e.target.value })} placeholder="Paste the email body or message text here..." rows="8" />
            <textarea value={emailForm.email_headers} onChange={(e) => setEmailForm({ ...emailForm, email_headers: e.target.value })} placeholder="Optional email headers (SPF/DKIM/DMARC evidence, Received lines)..." rows="5" />
            <input value={emailForm.sender_id} onChange={(e) => setEmailForm({ ...emailForm, sender_id: e.target.value })} placeholder="Optional sender display name or address" />
            <button className="primary-button" onClick={() => runScan("email", emailForm)} disabled={loading}>{loading ? "Analyzing..." : "Run Email Scan"}</button>
          </div>
        )}

        {type === "website" && (
          <div className="input-stack">
            <input value={websiteForm.url} onChange={(e) => setWebsiteForm({ ...websiteForm, url: e.target.value })} placeholder="https://example.com" />
            <button className="primary-button" onClick={() => runScan("website", websiteForm)} disabled={loading}>{loading ? "Analyzing..." : "Run Website Scan"}</button>
          </div>
        )}

        {type === "sms" && (
          <div className="input-stack">
            <textarea value={smsForm.message} onChange={(e) => setSmsForm({ ...smsForm, message: e.target.value })} placeholder="Paste the SMS message here..." rows="6" />
            <input value={smsForm.sender_id} onChange={(e) => setSmsForm({ ...smsForm, sender_id: e.target.value })} placeholder="Optional sender ID or phone number" />
            <input value={smsForm.extracted_url} onChange={(e) => setSmsForm({ ...smsForm, extracted_url: e.target.value })} placeholder="Optional suspicious link or URL" />
            <button className="primary-button" onClick={() => runScan("sms", smsForm)} disabled={loading}>{loading ? "Analyzing..." : "Run SMS Scan"}</button>
          </div>
        )}
      </section>

      <section className="panel result-panel">
        <div className="panel-heading">
          <div>
            <h3>Threat Assessment</h3>
            <p>Results from the current scan</p>
          </div>
        </div>

        {scanResults[type] ? (
          <div className="result-card">
            <div className="result-header">
              <div>
                <div className="eyebrow small">Score</div>
                <h2>{Math.round(scanResults[type].risk_score)}/100</h2>
              </div>
              <span className={`result-badge ${riskScoreClass(scanResults[type].risk_score)}`}>{scanResults[type].threat_level}</span>
            </div>

            <div className="score-grid">
              <div>
                <label>Confidence</label>
                <strong>{Math.round(scanResults[type].confidence_score)}/100</strong>
              </div>
              <div>
                <label>Status</label>
                <strong>{scanResults[type].status}</strong>
              </div>
            </div>

            <p className="summary-text">{scanResults[type].summary}</p>

            <div className="insight-block">
              <h4>Key Findings</h4>
              <ul>
                {scanResults[type].findings.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
              </ul>
            </div>

            <div className="insight-block">
              <h4>Recommended Actions</h4>
              <ul>
                {scanResults[type].recommendations.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
              </ul>
            </div>

            <button className="secondary-button" onClick={() => handleDownload(scanResults[type].scan_id)}>Download PDF Report</button>
          </div>
        ) : (
          <div className="empty-result">
            <ShieldCheck size={28} />
            <p>No scan result available yet. Run an analysis to view the threat assessment.</p>
          </div>
        )}
      </section>
    </div>
  );

  const renderHistory = () => (
    <div className="history-view">
      <div className="page-heading">
        <div>
          <div className="eyebrow">SCAN HISTORY</div>
          <h1>Persistent Threat Records</h1>
        </div>
      </div>

      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Scanner</th>
                <th>Summary</th>
                <th>Risk</th>
                <th>Classification</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.length ? history.map((item) => (
                <tr key={item.scan_id}>
                  <td>{item.scan_id.slice(0, 8)}</td>
                  <td>{item.scanner_type}</td>
                  <td>{item.summary}</td>
                  <td><span className={`risk-pill ${riskScoreClass(item.risk_score)}`}>{Math.round(item.risk_score)}</span></td>
                  <td>{item.threat_level}</td>
                  <td>
                    <div className="table-actions">
                      <button className="tiny-button" onClick={() => handleDownload(item.scan_id)}>PDF</button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="6" className="empty-state">No history found yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );

  const renderReports = () => (
    <div className="reports-view">
      <div className="page-heading">
        <div>
          <div className="eyebrow">REPORTS</div>
          <h1>Generated Security Reports</h1>
        </div>
      </div>

      <div className="report-grid">
        {history.length ? history.map((item) => (
          <div className="panel report-card" key={item.scan_id}>
            <div className="report-card-header">
              <span className="badge">{item.scanner_type}</span>
              <span className={`risk-pill ${riskScoreClass(item.risk_score)}`}>{Math.round(item.risk_score)}</span>
            </div>
            <h3>{item.summary || item.scanner_type}</h3>
            <p>{new Date(item.created_at).toLocaleString()}</p>
            <button className="primary-button" onClick={() => handleDownload(item.scan_id)}>Download PDF</button>
          </div>
        )) : (
          <div className="panel empty-report">No report artifacts are available until a scan is recorded.</div>
        )}
      </div>
    </div>
  );

  const selectView = () => {
    if (activePage === "Dashboard") return renderDashboard();
    if (activePage === "Email Scanner") return renderScanner("email", { title: "Email Phishing Scanner", caption: "Analyze sender trust, urgency, spoofing, and risky links." });
    if (activePage === "Website Scanner") return renderScanner("website", { title: "Website / URL Phishing Scanner", caption: "Review domain reputation, SSL posture, redirects, and suspicious content." });
    if (activePage === "SMS Scanner") return renderScanner("sms", { title: "SMS / Smishing Scanner", caption: "Review social-engineering tactics, required actions, and link risk." });
    if (activePage === "Scan History") return renderHistory();
    if (activePage === "Reports") return renderReports();
    return renderDashboard();
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <div>
            <h2>PhishGuard<span>AI</span></h2>
            <p>THREAT INTELLIGENCE</p>
          </div>
        </div>

        <div className="nav-label">Primary</div>
        <nav className="nav-list">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.name}
                className={`nav-item ${activePage === item.name ? "active" : ""}`}
                onClick={() => setActivePage(item.name)}
              >
                <Icon size={18} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="system-status">
            <span className="status-dot" />
            Detection Engine
            <span className="online">Online</span>
          </div>
        </div>
      </aside>

      <main className="content-shell">
        <header className="topbar">
          <div className="search-box">
            <Search size={16} />
            <input type="text" placeholder="Search scans or findings" />
          </div>

          <div className="topbar-actions">
            <button className="icon-button"><Bell size={17} /></button>
            <div className="user-pill">A</div>
          </div>
        </header>

        {error && <div className="global-alert">{error}</div>}

        <div className="main-panel">{selectView()}</div>
      </main>
    </div>
  );
}

function StatCard({ title, value, color, icon: Icon, change }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${color}`}>
        <Icon size={18} />
      </div>
      <p>{title}</p>
      <div className="stat-row">
        <h3>{typeof value === "number" ? value.toLocaleString() : value}</h3>
        <span>{change}</span>
      </div>
    </div>
  );
}

function QuickScanCard({ title, description, icon: Icon, onClick }) {
  return (
    <button className="quick-scan-card" onClick={onClick}>
      <div className="quick-scan-icon"><Icon size={18} /></div>
      <div>
        <strong>{title}</strong>
        <p>{description}</p>
      </div>
      <ArrowUpRight size={17} />
    </button>
  );
}

export default App;
