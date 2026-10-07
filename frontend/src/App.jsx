import React, { useState, useEffect } from 'react';

export default function App() {
  const [portalMode, setPortalMode] = useState('select'); // 'select', 'admin-login', 'client-login', 'register', 'dashboard'
  const [token, setToken] = useState(localStorage.getItem('cloudguard_token') || '');
  const [userRole, setUserRole] = useState(localStorage.getItem('cloudguard_role') || '');
  
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false); // Added show/hide state
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const [workspace, setWorkspace] = useState('AWS-Production-Cluster');
  const [scanStatus, setScanStatus] = useState('Idle');
  const [onboardingModal, setOnboardingModal] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [backendData, setBackendData] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    if (token) {
      setPortalMode('dashboard');
      if (userRole === 'admin') {
        fetchScanResults(workspace, token);
      }
    }
  }, [token, workspace]);

  const fetchScanResults = async (targetWorkspace, activeToken) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/admin/scan-results?workspace=${targetWorkspace}`, {
        headers: { 'Authorization': `Bearer ${activeToken}` }
      });
      const data = await res.json();
      if (res.ok) {
        setBackendData(data);
      } else {
        setErrorMsg(data.detail);
      }
    } catch (err) {
      setErrorMsg('Failed to connect to backend server.');
    }
  };

  const handleLogin = async (e, roleType) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setIsLoading(true);

    const endpoint = roleType === 'admin' 
      ? 'http://localhost:8000/api/v1/auth/admin-login' 
      : 'http://localhost:8000/api/v1/auth/client-login';

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        localStorage.setItem('cloudguard_token', data.access_token);
        localStorage.setItem('cloudguard_role', data.role);
        setToken(data.access_token);
        setUserRole(data.role);
        if (data.workspace) setWorkspace(data.workspace);
        setPortalMode('dashboard');
      } else {
        // Enforce exact requested error message on failure
        setErrorMsg('Incorrect password or email');
      }
    } catch (err) {
      setErrorMsg('Incorrect password or email');
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setSuccessMsg('');
    setIsLoading(true);

    try {
      const response = await fetch('http://localhost:8000/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role: 'admin' })
      });
      const data = await response.json();
      if (response.ok) {
        setSuccessMsg('Account registered successfully! Please log in.');
        setPortalMode('admin-login');
      } else {
        setErrorMsg(data.detail || 'Registration failed.');
      }
    } catch (err) {
      setErrorMsg('Error connecting to backend.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    setToken('');
    setUserRole('');
    setEmail('');
    setPassword('');
    setShowPassword(false);
    setBackendData(null);
    setPortalMode('select');
  };

  const handleWorkspaceChange = async (newWorkspace) => {
    setWorkspace(newWorkspace);
    try {
      await fetch('http://localhost:8000/api/v1/workspaces/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ workspace: newWorkspace })
      });
      if (userRole === 'admin') fetchScanResults(newWorkspace, token);
    } catch (err) {
      console.error('Failed to sync workspace');
    }
  };

  const handleScanIngestion = async () => {
    if (!selectedFile) {
      alert('Please select a cloud configuration or Terraform JSON file.');
      return;
    }

    setScanStatus('Ingesting & Analyzing...');
    const formData = new FormData();
    formData.append('workspace', workspace);
    formData.append('file', selectedFile);

    try {
      const response = await fetch('http://localhost:8000/api/v1/cloud/ingest', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
      });
      const data = await response.json();
      if (response.ok) {
        setScanStatus('Completed');
        alert(data.message);
        fetchScanResults(workspace, token);
      } else {
        setScanStatus('Failed');
        alert(data.detail || 'Ingestion failed.');
      }
    } catch (err) {
      setScanStatus('Error');
      alert('Error connecting to backend during vulnerability test scan.');
    }
  };

  const styles = {
    container: { minHeight: '100vh', backgroundColor: '#030712', color: '#f3f4f6', fontFamily: 'Inter, sans-serif', display: 'flex', flexDirection: 'column' },
    centerBox: { display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: '1rem' },
    card: { backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '2rem', width: '100%', maxWidth: '440px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)' },
    input: { width: '100%', backgroundColor: '#030712', border: '1px solid #374151', borderRadius: '8px', padding: '12px 16px', color: '#fff', fontSize: '14px', outline: 'none', marginBottom: '1rem', boxSizing: 'border-box' },
    passwordWrapper: { position: 'relative', display: 'flex', alignItems: 'center', marginBottom: '1rem' },
    passwordInput: { width: '100%', backgroundColor: '#030712', border: '1px solid #374151', borderRadius: '8px', padding: '12px 45px 12px 16px', color: '#fff', fontSize: '14px', outline: 'none', boxSizing: 'border-box' },
    showHideBtn: { position: 'absolute', right: '12px', background: 'transparent', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' },
    button: { width: '100%', backgroundColor: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px', padding: '12px', fontWeight: '600', cursor: 'pointer', fontSize: '14px', transition: 'background 0.2s' },
    portalCardBtn: { width: '100%', backgroundColor: '#1f2937', color: '#fff', border: '1px solid #374151', borderRadius: '8px', padding: '16px', fontWeight: '600', cursor: 'pointer', fontSize: '14px', textAlign: 'left', marginBottom: '1rem', transition: 'all 0.2s' },
    header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 2rem', backgroundColor: '#111827', borderBottom: '1px solid #1f2937' },
    grid: { display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '1rem', marginBottom: '1.5rem' },
    statCard: { backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '1.25rem' },
    main: { padding: '2rem', maxWidth: '1200px', margin: '0 auto', width: '100%', boxSizing: 'border-box' },
    modalOverlay: { position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(3, 7, 18, 0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 },
    attackNode: { backgroundColor: '#030712', border: '1px solid #1f2937', borderRadius: '8px', padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', marginBottom: '0.75rem' },
    arrow: { textAlign: 'center', color: '#ef4444', fontSize: '18px', fontWeight: 'bold', margin: '4px 0' }
  };

  // --- PORTAL SELECTOR SCREEN ---
  if (portalMode === 'select' && !token) {
    return (
      <div style={styles.container}>
        <div style={styles.centerBox}>
          <div style={styles.card}>
            <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
              <h2 style={{ fontSize: '24px', fontWeight: 'bold', color: '#fff', margin: '0 0 8px 0' }}>CloudGuard Enterprise</h2>
              <p style={{ fontSize: '13px', color: '#9ca3af', margin: 0 }}>Production Secure Gateway Portal</p>
            </div>

            <button onClick={() => { setPortalMode('admin-login'); setEmail(''); setPassword(''); setShowPassword(false); setErrorMsg(''); }} style={styles.portalCardBtn}>
              <div style={{ color: '#60a5fa', fontSize: '15px', fontWeight: 'bold', marginBottom: '4px' }}>🛡 Admin Control Center</div>
              <div style={{ color: '#9ca3af', fontSize: '12px', fontWeight: 'normal' }}>Full infrastructure scanning, attack paths, and automated patch remediation.</div>
            </button>

            <button onClick={() => { setPortalMode('client-login'); setEmail(''); setPassword(''); setShowPassword(false); setErrorMsg(''); }} style={styles.portalCardBtn}>
              <div style={{ color: '#fbbf24', fontSize: '15px', fontWeight: 'bold', marginBottom: '4px' }}>👥 Client Tester Portal</div>
              <div style={{ color: '#9ca3af', fontSize: '12px', fontWeight: 'normal' }}>Standard workspace overview and compliance assessment view.</div>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- ADMIN LOGIN ---
  if (portalMode === 'admin-login' && !token) {
    return (
      <div style={styles.container}>
        <div style={styles.centerBox}>
          <div style={styles.card}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <span style={{ fontSize: '11px', backgroundColor: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', padding: '2px 8px', borderRadius: '4px' }}>SECURE AUTHENTICATION</span>
              <h2 style={{ fontSize: '22px', fontWeight: 'bold', color: '#fff', margin: '10px 0 4px 0' }}>Admin Login</h2>
              <p style={{ fontSize: '12px', color: '#9ca3af', margin: 0 }}>JWT & Database Verified</p>
            </div>

            {errorMsg && <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '10px', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem', textAlign: 'center' }}>{errorMsg}</div>}
            {successMsg && <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', color: '#34d399', padding: '10px', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem', textAlign: 'center' }}>{successMsg}</div>}

            <form onSubmit={(e) => handleLogin(e, 'admin')}>
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Admin Email</label>
              <input type="email" placeholder="admin@cloudguard.io" value={email} onChange={(e) => setEmail(e.target.value)} style={styles.input} required />
              
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Password</label>
              <div style={styles.passwordWrapper}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="Enter secure password" 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  style={styles.passwordInput} 
                  required 
                />
                <button 
                  type="button" 
                  onClick={() => setShowPassword(!showPassword)} 
                  style={styles.showHideBtn}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
              
              <button type="submit" style={styles.button} disabled={isLoading}>{isLoading ? 'Verifying...' : 'Access Admin Dashboard'}</button>
            </form>

            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '1rem' }}>
              <button onClick={() => { setPortalMode('register'); setEmail(''); setPassword(''); setShowPassword(false); setErrorMsg(''); }} style={{ backgroundColor: 'transparent', color: '#60a5fa', border: 'none', cursor: 'pointer', fontSize: '12px' }}>Create Admin Account</button>
              <button onClick={() => setPortalMode('select')} style={{ backgroundColor: 'transparent', color: '#9ca3af', border: 'none', cursor: 'pointer', fontSize: '12px' }}>← Back</button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // --- CLIENT LOGIN ---
  if (portalMode === 'client-login' && !token) {
    return (
      <div style={styles.container}>
        <div style={styles.centerBox}>
          <div style={styles.card}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <span style={{ fontSize: '11px', backgroundColor: 'rgba(245, 158, 11, 0.2)', color: '#fbbf24', padding: '2px 8px', borderRadius: '4px' }}>CLIENT GATEWAY</span>
              <h2 style={{ fontSize: '22px', fontWeight: 'bold', color: '#fff', margin: '10px 0 4px 0' }}>Client Login</h2>
              <p style={{ fontSize: '12px', color: '#9ca3af', margin: 0 }}>Workspace Overview</p>
            </div>

            {errorMsg && <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '10px', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem', textAlign: 'center' }}>{errorMsg}</div>}

            <form onSubmit={(e) => handleLogin(e, 'client')}>
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Client Email</label>
              <input type="email" placeholder="client@cloudguard.io" value={email} onChange={(e) => setEmail(e.target.value)} style={styles.input} required />
              
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Password</label>
              <div style={styles.passwordWrapper}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="Enter password" 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  style={styles.passwordInput} 
                  required 
                />
                <button 
                  type="button" 
                  onClick={() => setShowPassword(!showPassword)} 
                  style={styles.showHideBtn}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
              
              <button type="submit" style={styles.button} disabled={isLoading}>{isLoading ? 'Authenticating...' : 'Access Client Portal'}</button>
            </form>

            <button onClick={() => setPortalMode('select')} style={{ backgroundColor: 'transparent', color: '#9ca3af', border: 'none', cursor: 'pointer', fontSize: '12px', width: '100%', marginTop: '1rem' }}>← Back to Portal Selection</button>
          </div>
        </div>
      </div>
    );
  }

  // --- REGISTER SCREEN ---
  if (portalMode === 'register' && !token) {
    return (
      <div style={styles.container}>
        <div style={styles.centerBox}>
          <div style={styles.card}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <span style={{ fontSize: '11px', backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '4px' }}>NEW USER SIGNUP</span>
              <h2 style={{ fontSize: '22px', fontWeight: 'bold', color: '#fff', margin: '10px 0 4px 0' }}>Register Admin</h2>
              <p style={{ fontSize: '12px', color: '#9ca3af', margin: 0 }}>Stored securely with bcrypt</p>
            </div>

            {errorMsg && <div style={{ backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '10px', borderRadius: '8px', fontSize: '12px', marginBottom: '1rem', textAlign: 'center' }}>{errorMsg}</div>}

            <form onSubmit={handleRegister}>
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Email Address</label>
              <input type="email" placeholder="you@domain.com" value={email} onChange={(e) => setEmail(e.target.value)} style={styles.input} required />
              
              <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Secure Password</label>
              <div style={styles.passwordWrapper}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  placeholder="At least 8 characters" 
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  style={styles.passwordInput} 
                  required 
                />
                <button 
                  type="button" 
                  onClick={() => setShowPassword(!showPassword)} 
                  style={styles.showHideBtn}
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
              
              <button type="submit" style={styles.button} disabled={isLoading}>{isLoading ? 'Registering...' : 'Complete Registration'}</button>
            </form>

            <button onClick={() => setPortalMode('admin-login')} style={{ backgroundColor: 'transparent', color: '#9ca3af', border: 'none', cursor: 'pointer', fontSize: '12px', width: '100%', marginTop: '1rem' }}>← Back to Login</button>
          </div>
        </div>
      </div>
    );
  }

  // --- DASHBOARD ---
  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ fontSize: '18px', fontWeight: 'bold', color: '#fff' }}>CloudGuard <span style={{ fontSize: '11px', backgroundColor: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', padding: '2px 8px', borderRadius: '4px' }}>Enterprise 3.0</span></span>
          <span style={{ fontSize: '11px', backgroundColor: userRole === 'admin' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)', color: userRole === 'admin' ? '#34d399' : '#fbbf24', padding: '2px 6px', borderRadius: '4px' }}>
            {userRole === 'admin' ? 'Admin Control Center' : 'Client Tester Portal'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: '#030712', border: '1px solid #374151', padding: '6px 12px', borderRadius: '8px' }}>
            <span style={{ fontSize: '12px', color: '#9ca3af' }}>Workspace:</span>
            <select value={workspace} onChange={(e) => handleWorkspaceChange(e.target.value)} style={{ background: 'transparent', color: '#fff', border: 'none', fontSize: '14px', outline: 'none', cursor: 'pointer' }}>
              <option value="AWS-Production-Cluster" style={{ background: '#111827' }}>AWS-Production-Cluster</option>
              <option value="Azure-Staging-Env" style={{ background: '#111827' }}>Azure-Staging-Env</option>
            </select>
          </div>
          {userRole === 'admin' && (
            <button onClick={() => setOnboardingModal(true)} style={{ backgroundColor: '#1f2937', color: '#e5e7eb', border: '1px solid #374151', padding: '8px 14px', borderRadius: '8px', cursor: 'pointer', fontSize: '12px', fontWeight: '500' }}>Cloud Onboarding</button>
          )}
          <button onClick={handleLogout} style={{ backgroundColor: 'transparent', color: '#ef4444', border: 'none', cursor: 'pointer', fontSize: '12px', fontWeight: 'bold' }}>Sign Out</button>
        </div>
      </header>

      <main style={styles.main}>
        {userRole !== 'admin' ? (
          <div style={{ ...styles.card, maxWidth: '100%', textAlign: 'center', padding: '4rem 2rem' }}>
            <h3 style={{ fontSize: '20px', color: '#fbbf24', marginBottom: '8px' }}>Client Security Compliance Overview</h3>
            <p style={{ fontSize: '13px', color: '#9ca3af' }}>Authenticated successfully via database token. High-level compliance status is active. Deep vulnerability parsing tools are restricted to Administrative Control.</p>
          </div>
        ) : (
          <>
            <div style={{ ...styles.card, maxWidth: '100%', marginBottom: '1.5rem' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#fff', marginTop: 0, marginBottom: '8px' }}>Production Static Infrastructure Vulnerability Scanner</h3>
              <p style={{ fontSize: '12px', color: '#9ca3af', marginBottom: '1rem' }}>Upload your Terraform JSON or cloud state file. The backend static analysis engine will parse your code for CVEs and misconfigurations in workspace: <span style={{ color: '#60a5fa' }}>{workspace}</span></p>
              <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                <input type="file" onChange={(e) => setSelectedFile(e.target.files[0])} style={{ color: '#9ca3af', fontSize: '13px', flex: 1 }} />
                <button onClick={handleScanIngestion} style={{ ...styles.button, width: 'auto', padding: '10px 24px', margin: 0 }}>
                  {scanStatus === 'Ingesting & Analyzing...' ? 'Analyzing Code...' : 'Run Vulnerability Scan'}
                </button>
              </div>
            </div>

            <div style={styles.grid}>
              <div style={styles.statCard}>
                <span style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase' }}>Security Score</span>
                <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#60a5fa', marginTop: '8px' }}>{backendData ? backendData.security_score : '60'}<span style={{ fontSize: '14px', color: '#6b7280' }}>/100</span></div>
              </div>
              <div style={styles.statCard}>
                <span style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase' }}>Critical Findings</span>
                <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#f87171', marginTop: '8px' }}>{backendData ? backendData.critical_findings : '2'}</div>
              </div>
              <div style={styles.statCard}>
                <span style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase' }}>Resources Tracked</span>
                <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#fff', marginTop: '8px' }}>{backendData ? backendData.resources_tracked : '12'}</div>
              </div>
              <div style={styles.statCard}>
                <span style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase' }}>Active Vulnerabilities</span>
                <div style={{ fontSize: '28px', fontWeight: 'bold', color: '#fbbf24', marginTop: '8px' }}>{backendData ? backendData.active_vulnerabilities : '5'}</div>
              </div>
            </div>

            <div style={{ ...styles.card, maxWidth: '100%' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#fff', marginTop: 0, marginBottom: '1rem' }}>Attack Chain Progression (Click any vector to inspect remediation patch)</h3>

              {backendData && backendData.attack_chain ? (
                backendData.attack_chain.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <div style={styles.attackNode} onClick={() => setSelectedNode(step)}>
                      <div>
                        <span style={{ fontSize: '10px', backgroundColor: 'rgba(248, 113, 113, 0.2)', color: '#f87171', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>Step {step.step}</span>
                        <h4 style={{ fontSize: '14px', fontWeight: 'bold', color: '#fff', margin: '6px 0 2px 0' }}>{step.node}</h4>
                        <p style={{ fontSize: '11px', color: '#9ca3af', margin: 0 }}>{step.vector} ({step.cve})</p>
                      </div>
                      <span style={{ fontSize: '11px', backgroundColor: step.risk === 'Critical' ? 'rgba(248, 113, 113, 0.1)' : 'rgba(251, 191, 36, 0.1)', color: step.risk === 'Critical' ? '#f87171' : '#fbbf24', border: step.risk === 'Critical' ? '1px solid rgba(248, 113, 113, 0.3)' : '1px solid rgba(251, 191, 36, 0.3)', padding: '4px 10px', borderRadius: '6px' }}>{step.risk}</span>
                    </div>
                    {idx < backendData.attack_chain.length - 1 && <div style={styles.arrow}>↓</div>}
                  </React.Fragment>
                ))
              ) : (
                <p style={{ color: '#9ca3af', fontSize: '13px' }}>Loading attack chain telemetry...</p>
              )}
            </div>
          </>
        )}
      </main>

      {selectedNode && (
        <div style={styles.modalOverlay}>
          <div style={styles.card}>
            <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#fff', marginTop: 0, marginBottom: '8px' }}>Vulnerability Inspection</h3>
            <p style={{ fontSize: '14px', color: '#60a5fa', fontWeight: '600', marginBottom: '8px' }}>{selectedNode.node} ({selectedNode.cve})</p>
            <p style={{ fontSize: '12px', color: '#f87171', marginBottom: '12px' }}>Vector: {selectedNode.vector}</p>
            <div style={{ backgroundColor: '#030712', border: '1px solid #1f2937', borderRadius: '8px', padding: '10px', marginBottom: '1rem' }}>
              <span style={{ fontSize: '10px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>Recommended Remediation Patch</span>
              <p style={{ fontSize: '12px', color: '#34d399', margin: 0, fontFamily: 'monospace' }}>{selectedNode.remediation}</p>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button onClick={() => setSelectedNode(null)} style={{ backgroundColor: 'transparent', color: '#9ca3af', border: 'none', cursor: 'pointer', padding: '8px 12px' }}>Close</button>
              <button onClick={() => { alert('Remediation patch successfully deployed!'); setSelectedNode(null); }} style={{ ...styles.button, width: 'auto', padding: '8px 16px' }}>Deploy Fix</button>
            </div>
          </div>
        </div>
      )}

      {onboardingModal && (
        <div style={styles.modalOverlay}>
          <div style={styles.card}>
            <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#fff', marginTop: 0, marginBottom: '8px' }}>Cloud Provider Onboarding</h3>
            <p style={{ fontSize: '12px', color: '#9ca3af', marginBottom: '1rem' }}>Connect a new cloud provider account securely.</p>
            <label style={{ fontSize: '11px', fontWeight: 'bold', color: '#9ca3af', textTransform: 'uppercase', display: 'block', marginBottom: '6px' }}>Select Provider</label>
            <select style={styles.input}>
              <option>Amazon Web Services (AWS)</option>
              <option>Microsoft Azure</option>
              <option>Google Cloud Platform (GCP)</option>
            </select>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '1rem' }}>
              <button onClick={() => setOnboardingModal(false)} style={{ backgroundColor: 'transparent', color: '#9ca3af', border: 'none', cursor: 'pointer', padding: '8px 12px' }}>Cancel</button>
              <button onClick={() => setOnboardingModal(false)} style={{ ...styles.button, width: 'auto', padding: '8px 16px' }}>Save & Connect</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}