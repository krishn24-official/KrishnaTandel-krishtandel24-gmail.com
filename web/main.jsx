import React, { useState, useEffect, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';

// API client
async function api(method, path, body = null, token = null) {
  const headers = {};
  if (token) headers['authorization'] = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';

  const res = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });

  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data?.error?.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.code = data?.error?.code;
    err.reason = data?.error?.reason;
    throw err;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Invite Acceptance View
// ---------------------------------------------------------------------------
function InviteAccept({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(false);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api('GET', `/v1/invites/${token}`)
      .then(setInvite)
      .catch(() => setError(true));
  }, [token]);

  if (error) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div data-testid="invite-error" className="error-banner">
            Invalid or expired invitation link. Please request a new invite.
          </div>
        </div>
      </div>
    );
  }

  if (!invite) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api('POST', `/v1/invites/${token}/accept`, { name, password });
      onAccepted();
    } catch (err) {
      setError(true);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div style={{ marginBottom: 20 }}>
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Accept Invitation</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
            Join as <span data-testid="invite-role" className="role-tag">{invite.role}</span>
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              data-testid="invite-email"
              className="form-input"
              value={invite.email || ''}
              readOnly
            />
          </div>

          <div className="form-group">
            <label className="form-label">Full Name</label>
            <input
              data-testid="invite-name"
              className="form-input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your name"
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              data-testid="invite-password"
              className="form-input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Choose a password"
              required
            />
          </div>

          <button data-testid="invite-submit" type="submit" className="btn-primary" disabled={submitting}>
            {submitting ? 'Accepting...' : 'Accept & Continue'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Login View
// ---------------------------------------------------------------------------
function LoginForm({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      setError('Email and password are required');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const data = await api('POST', '/v1/auth/login', { email: email.trim(), password });
      onLoginSuccess(data);
    } catch (err) {
      setError('Invalid email or password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <h1 className="logo-badge" style={{ fontSize: 24, marginBottom: 8 }}>RemoteOps</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: 14 }}>Sign in to your organization console</p>
        </div>

        {error && <div data-testid="login-error" className="error-banner">{error}</div>}

        <form data-testid="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              data-testid="login-email"
              type="email"
              className="form-input"
              placeholder="name@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              data-testid="login-password"
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <button data-testid="login-submit" type="submit" className="btn-primary" disabled={loading}>
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main App Component & Shell
// ---------------------------------------------------------------------------
export function App() {
  const [auth, setAuth] = useState(null); // { token, orgId, role, orgs }
  const [activeOrg, setActiveOrg] = useState(null); // { id, name, theme, role }
  const [permissions, setPermissions] = useState({});
  const [activeTab, setActiveTab] = useState('devices');
  const [inviteToken, setInviteToken] = useState(null);

  // Entities state
  const [devices, setDevices] = useState([]);
  const [members, setMembers] = useState([]);
  const [grants, setGrants] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  // Grant creation form state
  const [showNewGrant, setShowNewGrant] = useState(false);
  const [grantUser, setGrantUser] = useState('');
  const [grantDevice, setGrantDevice] = useState('');
  const [grantEffect, setGrantEffect] = useState('allow');
  const [grantPerms, setGrantPerms] = useState(new Set());

  // URL check for invite links on mount
  useEffect(() => {
    const path = window.location.pathname;
    if (path.startsWith('/invite/')) {
      const tok = path.slice('/invite/'.length).replace(/\/$/, '');
      if (tok) setInviteToken(tok);
    }
  }, []);

  // Restore session on mount
  useEffect(() => {
    if (window.location.pathname.startsWith('/invite/')) return;
    api('POST', '/v1/auth/refresh')
      .then(async (data) => {
        const me = await api('GET', '/v1/auth/me', null, data.token);
        setAuth(data);
        const curOrg = data.orgs.find((o) => o.id === data.orgId) || data.orgs[0];
        setActiveOrg(curOrg);
        setPermissions(me.permissions || {});
      })
      .catch(() => {});
  }, []);

  // Load context on login
  const handleLoginSuccess = async (loginData) => {
    try {
      const me = await api('GET', '/v1/auth/me', null, loginData.token);
      setAuth(loginData);
      const curOrg = loginData.orgs.find((o) => o.id === loginData.orgId) || loginData.orgs[0];
      setActiveOrg(curOrg);
      setPermissions(me.permissions || {});
      setActiveTab('devices');
    } catch (err) {
      console.error('Failed to load initial context:', err);
    }
  };

  // Switch active organization
  const switchOrg = async (targetOrgId) => {
    if (!auth?.token || targetOrgId === activeOrg?.id) return;
    try {
      const switchRes = await api('POST', '/v1/auth/token', { orgId: targetOrgId }, auth.token);
      const newAuth = { ...auth, token: switchRes.token, orgId: switchRes.orgId, role: switchRes.role };
      const me = await api('GET', '/v1/auth/me', null, switchRes.token);

      setAuth(newAuth);
      const curOrg = newAuth.orgs.find((o) => o.id === targetOrgId) || { id: targetOrgId, theme: 'cobalt', name: targetOrgId };
      setActiveOrg(curOrg);
      setPermissions(me.permissions || {});
      setActiveTab('devices');
    } catch (err) {
      console.error('Failed to switch organization:', err);
    }
  };

  // Create new organization
  const handleCreateOrg = async () => {
    const name = window.prompt('Organization Name');
    if (!name || !name.trim()) return;

    try {
      const newOrg = await api('POST', '/v1/orgs', { name: name.trim() }, auth.token);
      // Mint token for new org
      const tokenRes = await api('POST', '/v1/auth/token', { orgId: newOrg.id }, auth.token);
      const updatedOrgs = [...auth.orgs, newOrg];
      const newAuth = { ...auth, token: tokenRes.token, orgId: newOrg.id, role: 'owner', orgs: updatedOrgs };
      const me = await api('GET', '/v1/auth/me', null, tokenRes.token);

      setAuth(newAuth);
      setActiveOrg(newOrg);
      setPermissions(me.permissions || {});
      setDevices([]);
      setActiveTab('devices');
    } catch (err) {
      console.error('Failed to create organization:', err);
    }
  };

  // Fetch data per tab
  const fetchData = useCallback(async () => {
    if (!auth?.token || !activeOrg?.id) return;

    if (activeTab === 'devices') {
      try {
        const res = await api('GET', `/v1/orgs/${activeOrg.id}/devices`, null, auth.token);
        setDevices(res.devices || []);
      } catch {
        setDevices([]);
      }
    } else if (activeTab === 'people') {
      try {
        const res = await api('GET', `/v1/orgs/${activeOrg.id}/members`, null, auth.token);
        setMembers(res.members || []);
      } catch {
        setMembers([]);
      }
    } else if (activeTab === 'grants') {
      try {
        const [gRes, mRes, dRes] = await Promise.all([
          api('GET', `/v1/orgs/${activeOrg.id}/grants`, null, auth.token).catch(() => ({ grants: [] })),
          api('GET', `/v1/orgs/${activeOrg.id}/members`, null, auth.token).catch(() => ({ members: [] })),
          api('GET', `/v1/orgs/${activeOrg.id}/devices`, null, auth.token).catch(() => ({ devices: [] })),
        ]);
        setGrants(gRes.grants || []);
        setMembers(mRes.members || []);
        setDevices(dRes.devices || []);
      } catch {
        setGrants([]);
      }
    } else if (activeTab === 'sessions') {
      try {
        const res = await api('GET', `/v1/orgs/${activeOrg.id}/sessions`, null, auth.token);
        setSessions(res.sessions || []);
      } catch {
        setSessions([]);
      }
    } else if (activeTab === 'audit') {
      try {
        const res = await api('GET', `/v1/orgs/${activeOrg.id}/audit?limit=50`, null, auth.token);
        setAuditLogs(res.events || []);
      } catch {
        setAuditLogs([]);
      }
    }
  }, [auth?.token, activeOrg?.id, activeTab]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Session start
  const handleStartSession = async (deviceId, mode) => {
    try {
      await api('POST', `/v1/orgs/${activeOrg.id}/sessions`, { deviceId, mode }, auth.token);
      alert(`Session started in ${mode} mode`);
      fetchData();
    } catch (err) {
      alert(`Could not start session: ${err.message}`);
    }
  };

  // Grant submit
  const handleCreateGrant = async () => {
    if (!grantUser || grantPerms.size === 0) {
      alert('Please select a member and at least one permission');
      return;
    }

    try {
      await api('POST', `/v1/orgs/${activeOrg.id}/grants`, {
        userId: grantUser,
        deviceId: grantDevice || null,
        effect: grantEffect,
        permissions: [...grantPerms],
      }, auth.token);

      setShowNewGrant(false);
      setGrantPerms(new Set());
      setGrantUser('');
      setGrantDevice('');
      fetchData();
    } catch (err) {
      alert(`Failed to create grant: ${err.message}`);
    }
  };

  const handleRevokeGrant = async (grantId) => {
    try {
      await api('DELETE', `/v1/orgs/${activeOrg.id}/grants/${grantId}`, null, auth.token);
      fetchData();
    } catch (err) {
      alert(`Failed to revoke grant: ${err.message}`);
    }
  };

  const handleRenameOrg = async () => {
    const name = window.prompt('New organization name', activeOrg?.name);
    if (!name || !name.trim()) return;

    try {
      const updated = await api('PATCH', `/v1/orgs/${activeOrg.id}`, { name: name.trim() }, auth.token);
      setActiveOrg((prev) => ({ ...prev, name: updated.name }));
      setAuth((prev) => ({
        ...prev,
        orgs: prev.orgs.map((o) => (o.id === updated.id ? { ...o, name: updated.name } : o)),
      }));
    } catch (err) {
      alert(`Rename failed: ${err.message}`);
    }
  };

  const handleDeleteOrg = async () => {
    if (!window.confirm('Are you sure you want to delete this organization?')) return;
    try {
      await api('DELETE', `/v1/orgs/${activeOrg.id}`, null, auth.token);
      window.location.reload();
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    }
  };

  // Invite acceptance view
  if (inviteToken) {
    return (
      <InviteAccept
        token={inviteToken}
        onAccepted={() => {
          setInviteToken(null);
          window.history.pushState({}, '', '/');
        }}
      />
    );
  }

  // Login view
  if (!auth?.token || !activeOrg) {
    return <LoginForm onLoginSuccess={handleLoginSuccess} />;
  }

  // Navigation permissions
  const canDevices = permissions['device:list']?.effect === 'allow';
  const canPeople = permissions['user:read']?.effect === 'allow';
  const canGrants = permissions['user:read']?.effect === 'allow' || permissions['grant:create']?.effect === 'allow' || permissions['grant:revoke']?.effect === 'allow';
  const canSessions = permissions['session:view']?.effect === 'allow' || permissions['session:start']?.effect === 'allow';
  const canAudit = permissions['audit:read']?.effect === 'allow';
  const canAdmin = permissions['org:update']?.effect === 'allow' || permissions['org:delete']?.effect === 'allow';

  return (
    <div
      data-testid="app-shell"
      data-org-id={activeOrg.id}
      data-org-theme={activeOrg.theme}
    >
      {/* Top Header */}
      <header className="top-header">
        <div className="logo-group">
          <span className="logo-badge">RemoteOps</span>

          <div className="org-selector">
            {auth.orgs.map((o) => (
              <button
                key={o.id}
                data-testid="org-option"
                data-org-id={o.id}
                className={`org-btn ${o.id === activeOrg.id ? 'active' : ''}`}
                onClick={() => switchOrg(o.id)}
              >
                {o.name}
              </button>
            ))}
            <button data-testid="create-org" className="create-org-btn" onClick={handleCreateOrg}>
              + Create Org
            </button>
          </div>
        </div>

        <div className="user-badge">
          <span data-testid="active-role" className="role-tag">
            {auth.role}
          </span>
          <button
            className="action-btn"
            style={{ margin: 0 }}
            onClick={() => {
              setAuth(null);
              setActiveOrg(null);
            }}
          >
            Sign Out
          </button>
        </div>
      </header>

      {/* Permission-driven Nav Cards */}
      <nav className="nav-bar">
        {canDevices && (
          <button
            data-testid="nav-devices"
            className={`nav-card-btn ${activeTab === 'devices' ? 'active' : ''}`}
            onClick={() => setActiveTab('devices')}
          >
            Devices
          </button>
        )}

        {canPeople && (
          <button
            data-testid="nav-people"
            className={`nav-card-btn ${activeTab === 'people' ? 'active' : ''}`}
            onClick={() => setActiveTab('people')}
          >
            People
          </button>
        )}

        {canGrants && (
          <button
            data-testid="nav-grants"
            className={`nav-card-btn ${activeTab === 'grants' ? 'active' : ''}`}
            onClick={() => setActiveTab('grants')}
          >
            Grants
          </button>
        )}

        {canSessions && (
          <button
            data-testid="nav-sessions"
            className={`nav-card-btn ${activeTab === 'sessions' ? 'active' : ''}`}
            onClick={() => setActiveTab('sessions')}
          >
            Sessions
          </button>
        )}

        {canAudit && (
          <button
            data-testid="nav-audit"
            data-permission="audit:read"
            data-state="unlocked"
            className={`nav-card-btn ${activeTab === 'audit' ? 'active' : ''}`}
            onClick={() => setActiveTab('audit')}
          >
            Audit Log
          </button>
        )}

        {canAdmin && (
          <button
            data-testid="nav-admin"
            className={`nav-card-btn ${activeTab === 'admin' ? 'active' : ''}`}
            onClick={() => setActiveTab('admin')}
          >
            Admin
          </button>
        )}
      </nav>

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'devices' && canDevices && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Fleet Devices</h2>
            </div>

            {devices.length === 0 ? (
              <div data-testid="devices-empty" className="empty-state">
                No devices found in this organization.
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Platform</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                      <td style={{ fontWeight: 600 }}>{d.name}</td>
                      <td style={{ textTransform: 'capitalize', color: 'var(--text-muted)' }}>{d.kind}</td>
                      <td>
                        <span className={`status-dot ${d.online ? 'online' : 'offline'}`} />
                        {d.online ? 'Online' : 'Offline'}
                      </td>
                      <td>
                        {d.permissions?.['device:control']?.effect === 'allow' && (
                          <button
                            data-permission="device:control"
                            data-state="unlocked"
                            className="action-btn"
                            onClick={() => handleStartSession(d.id, 'control')}
                          >
                            Control
                          </button>
                        )}
                        {d.permissions?.['device:terminal']?.effect === 'allow' && (
                          <button
                            data-permission="device:terminal"
                            data-state="unlocked"
                            className="action-btn"
                            onClick={() => handleStartSession(d.id, 'terminal')}
                          >
                            Terminal
                          </button>
                        )}
                        {d.permissions?.['device:view']?.effect === 'allow' && (
                          <button
                            data-permission="device:view"
                            data-state="unlocked"
                            className="action-btn"
                            onClick={() => handleStartSession(d.id, 'view')}
                          >
                            View
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'people' && canPeople && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Members & Team</h2>
            </div>

            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id} data-testid="user-row" data-user-id={m.id}>
                    <td style={{ fontWeight: 600 }}>{m.name || '—'}</td>
                    <td>{m.email}</td>
                    <td>
                      <span className="role-tag">{m.role}</span>
                    </td>
                    <td style={{ textTransform: 'capitalize', color: 'var(--text-muted)' }}>{m.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'grants' && canGrants && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Authorization Grants</h2>
              {permissions['grant:create']?.effect === 'allow' && (
                <button
                  data-testid="new-grant"
                  className="action-btn"
                  onClick={() => setShowNewGrant(!showNewGrant)}
                >
                  {showNewGrant ? 'Cancel' : '+ New Grant'}
                </button>
              )}
            </div>

            {showNewGrant && (
              <div style={{ background: 'rgba(0,0,0,0.2)', padding: 18, borderRadius: 8, marginBottom: 20 }}>
                <h3 style={{ fontSize: 14, marginBottom: 12 }}>Create Grant</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 16 }}>
                  <div>
                    <label className="form-label">Member</label>
                    <select
                      data-testid="grant-user"
                      className="form-select"
                      value={grantUser}
                      onChange={(e) => setGrantUser(e.target.value)}
                    >
                      <option value="">Select Member</option>
                      {members.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.name || m.email} ({m.role})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="form-label">Device Scope</label>
                    <select
                      data-testid="grant-device"
                      className="form-select"
                      value={grantDevice}
                      onChange={(e) => setGrantDevice(e.target.value)}
                    >
                      <option value="">All Devices (Org-wide)</option>
                      {devices.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="form-label">Effect</label>
                    <select
                      data-testid="grant-effect"
                      className="form-select"
                      value={grantEffect}
                      onChange={(e) => setGrantEffect(e.target.value)}
                    >
                      <option value="allow">allow</option>
                      <option value="deny">deny</option>
                    </select>
                  </div>
                </div>

                <div style={{ marginBottom: 16 }}>
                  <label className="form-label">Permissions</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
                    {['device:terminal', 'device:control', 'device:view', 'device:reboot', 'session:start', 'audit:read'].map((perm) => (
                      <label key={perm} style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                        <input
                          type="checkbox"
                          data-permission-key={perm}
                          checked={grantPerms.has(perm)}
                          onChange={(e) => {
                            const next = new Set(grantPerms);
                            if (e.target.checked) next.add(perm);
                            else next.delete(perm);
                            setGrantPerms(next);
                          }}
                        />
                        {perm}
                      </label>
                    ))}
                  </div>
                </div>

                <button data-testid="grant-submit" className="action-btn" onClick={handleCreateGrant}>
                  Submit Grant
                </button>
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {grants.length === 0 ? (
                <div className="empty-state">No active grants found.</div>
              ) : (
                grants.map((g) => (
                  <div
                    key={g.id}
                    data-testid="grant-row"
                    data-effect={g.effect}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 16px',
                      background: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-color)',
                      borderRadius: 'var(--radius-sm)',
                    }}
                  >
                    <div>
                      <span
                        className="role-tag"
                        style={{
                          backgroundColor: g.effect === 'allow' ? 'rgba(16,185,129,0.15)' : 'rgba(244,63,94,0.15)',
                          color: g.effect === 'allow' ? '#34d399' : '#fb7185',
                          borderColor: g.effect === 'allow' ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)',
                          marginRight: 10,
                        }}
                      >
                        {g.effect}
                      </span>
                      <strong style={{ marginRight: 10 }}>User: {g.user_id}</strong>
                      <span style={{ color: 'var(--text-muted)', marginRight: 10 }}>
                        Target: {g.device_id || 'Entire Organization'}
                      </span>
                      <code style={{ fontSize: 12, color: 'var(--accent-color)' }}>
                        {Array.isArray(g.permissions) ? g.permissions.join(', ') : g.permissions}
                      </code>
                    </div>

                    {permissions['grant:revoke']?.effect === 'allow' && (
                      <button
                        data-testid="revoke-grant"
                        className="action-btn danger"
                        onClick={() => handleRevokeGrant(g.id)}
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'sessions' && canSessions && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Active & Past Sessions</h2>
            </div>

            {sessions.length === 0 ? (
              <div className="empty-state">No sessions recorded yet.</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Session ID</th>
                    <th>Device</th>
                    <th>Mode</th>
                    <th>State</th>
                    <th>Started</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((s) => (
                    <tr key={s.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{s.id}</td>
                      <td>{s.device_id}</td>
                      <td style={{ textTransform: 'capitalize' }}>{s.mode}</td>
                      <td>
                        <span className={`status-dot ${s.state === 'active' ? 'online' : 'offline'}`} />
                        {s.state}
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{s.started_at?.slice(0, 19).replace('T', ' ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'audit' && canAudit && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Immutable Audit Trail</h2>
            </div>

            {auditLogs.length === 0 ? (
              <div className="empty-state">No audit events recorded yet.</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Actor</th>
                    <th>Target</th>
                    <th>Result</th>
                    <th>Reason</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((e) => (
                    <tr key={e.id}>
                      <td style={{ fontWeight: 600 }}>{e.action}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{e.actor_id}</td>
                      <td>{e.target_type}: {e.target_id}</td>
                      <td>
                        <span
                          className="role-tag"
                          style={{
                            backgroundColor: e.result === 'allow' ? 'rgba(16,185,129,0.15)' : 'rgba(244,63,94,0.15)',
                            color: e.result === 'allow' ? '#34d399' : '#fb7185',
                            borderColor: e.result === 'allow' ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)',
                          }}
                        >
                          {e.result}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-muted)' }}>{e.reason_code || '—'}</td>
                      <td style={{ color: 'var(--text-muted)' }}>{e.created_at?.slice(0, 19).replace('T', ' ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {activeTab === 'admin' && canAdmin && (
          <div className="view-card">
            <div className="view-header">
              <h2 className="view-title">Organization Settings</h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ padding: 16, background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)' }}>
                <h4 style={{ marginBottom: 6 }}>Organization Details</h4>
                <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 12 }}>
                  Name: <strong>{activeOrg.name}</strong> · ID: <code>{activeOrg.id}</code> · Theme: <code>{activeOrg.theme}</code>
                </p>
                {permissions['org:update']?.effect === 'allow' && (
                  <button data-testid="rename-org" className="action-btn" onClick={handleRenameOrg}>
                    Rename Organization
                  </button>
                )}
              </div>

              {permissions['org:delete']?.effect === 'allow' && (
                <div style={{ padding: 16, background: 'rgba(244,63,94,0.04)', border: '1px solid rgba(244,63,94,0.2)', borderRadius: 'var(--radius-sm)' }}>
                  <h4 style={{ color: '#fb7185', marginBottom: 6 }}>Danger Zone</h4>
                  <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 12 }}>
                    Deleting an organization permanently marks it as deleted. This operation requires owner authority.
                  </p>
                  <button data-testid="delete-org" className="action-btn danger" onClick={handleDeleteOrg}>
                    Delete Organization
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<App />);
}
