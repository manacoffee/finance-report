import { useState, useRef, useEffect } from 'react';
import * as XLSX from 'xlsx';
import Head from 'next/head';

const GST = 0.1;
const exGST = v => v / (1 + GST);
const fmt = n => `$${Number(n).toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const pct = (a, b) => b === 0 ? '—' : `${((a / b) * 100).toFixed(1)}%`;

const Btn = ({ onClick, children, variant = 'dark', disabled, small }) => {
  const base = { border: 'none', borderRadius: 7, cursor: disabled ? 'not-allowed' : 'pointer', fontWeight: 600, opacity: disabled ? 0.6 : 1, fontSize: small ? 12 : 14 };
  const styles = {
    dark: { ...base, background: '#1a1a2e', color: '#fff', padding: small ? '6px 12px' : '11px 20px' },
    outline: { ...base, background: '#fff', color: '#1a1a2e', border: '1px solid #ccc', padding: small ? '5px 11px' : '10px 19px' },
    green: { ...base, background: '#16a34a', color: '#fff', padding: small ? '6px 12px' : '11px 20px' },
    xero: { ...base, background: '#13B5EA', color: '#fff', padding: small ? '6px 12px' : '11px 20px' },
  };
  return <button style={styles[variant] || styles.dark} onClick={onClick} disabled={disabled}>{children}</button>;
};

const Field = ({ label, value, onChange, prefix = '$', readOnly }) => (
  <div style={{ marginBottom: 9 }}>
    <label style={{ display: 'block', fontSize: 11, color: '#555', marginBottom: 2 }}>{label}</label>
    <div style={{ display: 'flex', alignItems: 'center', border: `1px solid ${readOnly ? '#b7e2c8' : '#ddd'}`, borderRadius: 6, overflow: 'hidden', background: readOnly ? '#f0faf4' : '#fff' }}>
      <span style={{ padding: '7px 9px', background: readOnly ? '#d1f5e0' : '#f4f4f4', color: '#888', fontSize: 12 }}>{prefix}</span>
      <input type="number" value={value} onChange={e => onChange && onChange(e.target.value)} readOnly={readOnly}
        style={{ flex: 1, border: 'none', padding: '7px 9px', fontSize: 13, outline: 'none', background: 'transparent' }} placeholder="0.00" min="0" />
      {readOnly && <span style={{ fontSize: 10, color: '#16a34a', padding: '0 8px' }}>● auto</span>}
    </div>
  </div>
);

const KPICard = ({ label, value, sub, highlight }) => (
  <div style={{ background: highlight ? '#1a1a2e' : '#fff', color: highlight ? '#fff' : '#222', border: '1px solid #e0e0e0', borderRadius: 10, padding: '12px 14px', boxShadow: '0 1px 4px rgba(0,0,0,0.05)' }}>
    <div style={{ fontSize: 10, color: highlight ? '#aab' : '#888', marginBottom: 3, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
    <div style={{ fontSize: 19, fontWeight: 700 }}>{value}</div>
    {sub && <div style={{ fontSize: 10, color: highlight ? '#ccd' : '#999', marginTop: 2 }}>{sub}</div>}
  </div>
);

const Tag = ({ color, children }) => (
  <span style={{ background: color + '20', color, fontSize: 11, padding: '2px 8px', borderRadius: 20, fontWeight: 600 }}>{children}</span>
);

function parseLightspeedExcel(wb) {
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1 });
  let coffeeInc = 0, foodInc = 0, transactions = 0;
  for (const row of rows) {
    const cat = String(row[0] || '').toLowerCase();
    const rev = parseFloat(row[1]) || 0;
    const txn = parseInt(row[2]) || 0;
    if (cat.includes('coffee') || cat.includes('bev')) { coffeeInc += rev; transactions += txn; }
    else if (cat.includes('food') || cat.includes('kitchen')) { foodInc += rev; transactions += txn; }
  }
  if (coffeeInc === 0 && foodInc === 0) {
    const json = XLSX.utils.sheet_to_json(ws);
    for (const row of json) {
      const getVal = kw => { const k = Object.keys(row).find(k => k.toLowerCase().includes(kw)); return k ? parseFloat(row[k]) || 0 : 0; };
      coffeeInc += getVal('coffee'); foodInc += getVal('food');
      transactions += getVal('transaction') || getVal('count');
    }
  }
  return { turnoverCoffeeInc: coffeeInc.toFixed(2), turnoverFoodInc: foodInc.toFixed(2), transactions: transactions || '' };
}

export default function App() {
  const [step, setStep] = useState('input');
  const [tab, setTab] = useState('manual');
  const [weekLabel, setWeekLabel] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [inputs, setInputs] = useState({ turnoverCoffeeInc: '', turnoverFoodInc: '', cogsCoffeeInc: '', cogsFoodInc: '', labourExGST: '', transactions: '' });
  const [autoFields, setAutoFields] = useState({});
  const [invoices, setInvoices] = useState([]);
  const [log, setLog] = useState([]);
  const [parsing, setParsing] = useState(false);
  const [xeroStatus, setXeroStatus] = useState('disconnected');
  const [xeroLoading, setXeroLoading] = useState(false);
  const [aiReport, setAiReport] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');
  const pdfRef = useRef();
  const lsRef = useRef();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('xero') === 'connected') {
      setXeroStatus('connected');
      addLog('✓ Xero connected successfully');
      window.history.replaceState({}, '', '/');
    } else if (params.get('xero') === 'error') {
      setXeroStatus('error');
      addLog('✗ Xero connection failed — please try again');
      window.history.replaceState({}, '', '/');
    }
  }, []);

  const addLog = msg => setLog(l => [...l, msg]);
  const set = k => v => setInputs(p => ({ ...p, [k]: v }));
  const merged = { ...inputs, ...autoFields };
  const n = k => parseFloat(merged[k]) || 0;

  const coffeeEx = exGST(n('turnoverCoffeeInc'));
  const foodEx = exGST(n('turnoverFoodInc'));
  const cogsCoEx = exGST(n('cogsCoffeeInc'));
  const cogsFdEx = exGST(n('cogsFoodInc'));
  const labourEx = n('labourExGST');
  const txns = n('transactions');
  const total = coffeeEx + foodEx;
  const totalCOGS = cogsCoEx + cogsFdEx;
  const gp = total - totalCOGS;
  const gpPct = total > 0 ? (gp / total) * 100 : 0;
  const labourPct = total > 0 ? (labourEx / total) * 100 : 0;
  const avg = txns > 0 ? total / txns : 0;

  const invoiceCoffee = invoices.filter(i => i.category === 'coffee').reduce((s, i) => s + (i.total_inc_gst || 0), 0);
  const invoiceFood = invoices.filter(i => i.category === 'food').reduce((s, i) => s + (i.total_inc_gst || 0), 0);
  const invoiceUncat = invoices.filter(i => !i.category);

  const applyInvoiceToCOGS = () => {
    setAutoFields(p => ({
      ...p,
      cogsCoffeeInc: ((parseFloat(p.cogsCoffeeInc) || 0) + invoiceCoffee).toFixed(2),
      cogsFoodInc: ((parseFloat(p.cogsFoodInc) || 0) + invoiceFood).toFixed(2),
    }));
    addLog(`✓ Applied: Coffee COGS +${fmt(invoiceCoffee)}, Food COGS +${fmt(invoiceFood)}`);
  };

  const fetchXeroLabour = async () => {
    if (!fromDate || !toDate) { addLog('⚠ Enter From and To dates first'); return; }
    setXeroLoading(true);
    addLog(`Fetching labour from Xero (${fromDate} → ${toDate})…`);
    try {
      const res = await fetch(`/api/xero-labour?fromDate=${fromDate}&toDate=${toDate}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setAutoFields(p => ({ ...p, labourExGST: data.labourExGST.toFixed(2) }));
      addLog(`✓ Xero labour: ${fmt(data.labourExGST)} ex-GST`);
    } catch (e) {
      addLog(`✗ Xero error: ${e.message}`);
      if (e.message.includes('reconnect')) setXeroStatus('disconnected');
    }
    setXeroLoading(false);
  };

  const handlePDFs = async files => {
    setParsing(true);
    for (const f of files) {
      addLog(`Reading ${f.name}…`);
      const b64 = await new Promise((res, rej) => {
        const r = new FileReader(); r.onload = () => res(r.result.split(',')[1]); r.onerror = rej; r.readAsDataURL(f);
      });
      try {
        const res = await fetch('/api/parse-invoice', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base64: b64, filename: f.name }) });
        const inv = await res.json();
        setInvoices(p => [...p, inv]);
        addLog(`✓ ${inv.supplier || f.name} — ${fmt(inv.total_inc_gst || 0)} (${inv.category || '⚠ unrecognised'})`);
      } catch { addLog(`✗ ${f.name} — failed`); }
    }
    setParsing(false);
  };

  const handleLightspeed = async files => {
    const f = files[0]; if (!f) return;
    try {
      const buf = await f.arrayBuffer();
      const wb = XLSX.read(buf, { type: 'array' });
      const vals = parseLightspeedExcel(wb);
      setAutoFields(p => ({ ...p, ...vals }));
      addLog(`✓ Lightspeed: Coffee ${fmt(exGST(parseFloat(vals.turnoverCoffeeInc) || 0))}, Food ${fmt(exGST(parseFloat(vals.turnoverFoodInc) || 0))} ex-GST`);
    } catch { addLog('✗ Could not parse Lightspeed file'); }
  };

  const generateAI = async () => {
    setAiLoading(true); setAiError(''); setAiReport('');
    try {
      const res = await fetch('/api/generate-report', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ weekLabel, coffeeEx, foodEx, total, cogsCoEx, cogsFdEx, totalCOGS, gp, gpPct, labourEx, labourPct, txns, avg }),
      });
      const data = await res.json();
      setAiReport(data.report || '');
      setStep('ai');
    } catch { setAiError('Failed — please try again.'); }
    setAiLoading(false);
  };

  const isAuto = k => autoFields[k] !== undefined;
  const renderBold = txt => txt.split(/(\*\*[^*]+\*\*)/).map((s, i) => s.startsWith('**') ? <strong key={i}>{s.slice(2, -2)}</strong> : s);

  const TabBtn = ({ id, label }) => (
    <button onClick={() => setTab(id)} style={{ flex: 1, padding: '9px 0', background: tab === id ? '#1a1a2e' : '#f4f4f4', color: tab === id ? '#fff' : '#555', border: 'none', cursor: 'pointer', fontWeight: 600, fontSize: 13, borderRadius: id === 'manual' ? '7px 0 0 7px' : '0 7px 7px 0' }}>
      {label}
    </button>
  );

  if (step === 'ai') return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 680, margin: '0 auto', padding: 20 }}>
      <Head><title>Weekly Finance Report</title></Head>
      <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
        <Btn onClick={() => setStep('report')} variant="outline" small>← Back</Btn>
        <h2 style={{ margin: 0, fontSize: 17 }}>AI Analysis — {weekLabel || 'This Week'}</h2>
      </div>
      <div style={{ background: '#f9f9fb', border: '1px solid #e0e0e0', borderRadius: 12, padding: 20, fontSize: 13, color: '#333', lineHeight: 1.75 }}>
        {aiReport.split('\n').map((l, i) => <p key={i} style={{ margin: '5px 0' }}>{renderBold(l)}</p>)}
      </div>
      <div style={{ marginTop: 14 }}><Btn onClick={() => { setStep('input'); setAiReport(''); }}>New Report</Btn></div>
    </div>
  );

  if (step === 'report') return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 680, margin: '0 auto', padding: 20 }}>
      <Head><title>Weekly Finance Report</title></Head>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 4 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 19 }}>Weekly Financial Report</h2>
          <div style={{ color: '#888', fontSize: 12 }}>{weekLabel || 'Week ending —'} · All figures ex-GST</div>
        </div>
        <Btn onClick={() => setStep('input')} variant="outline" small>← Edit</Btn>
      </div>
      <hr style={{ border: 'none', borderTop: '1px solid #eee', margin: '12px 0' }} />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 9, marginBottom: 9 }}>
        <KPICard label="Turnover — Coffee" value={fmt(coffeeEx)} sub={`${pct(coffeeEx, total)} of total`} />
        <KPICard label="Turnover — Food & Bev" value={fmt(foodEx)} sub={`${pct(foodEx, total)} of total`} />
        <KPICard label="COGS — Coffee" value={fmt(cogsCoEx)} sub={`${pct(cogsCoEx, coffeeEx)} COGS ratio`} />
        <KPICard label="COGS — Food & Bev" value={fmt(cogsFdEx)} sub={`${pct(cogsFdEx, foodEx)} COGS ratio`} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 9, marginBottom: 9 }}>
        <KPICard label="Total Turnover" value={fmt(total)} highlight />
        <KPICard label="Gross Profit" value={fmt(gp)} sub={`Margin: ${gpPct.toFixed(1)}%`} highlight />
        <KPICard label="Total COGS" value={fmt(totalCOGS)} sub={`${pct(totalCOGS, total)} of revenue`} highlight />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 9, marginBottom: 18 }}>
        <KPICard label="Labour" value={fmt(labourEx)} sub={`${labourPct.toFixed(1)}% of turnover`} />
        <KPICard label="Transactions" value={txns.toLocaleString()} />
        <KPICard label="Avg Customer Spend" value={fmt(avg)} sub="ex-GST per transaction" />
      </div>
      <Btn onClick={generateAI} disabled={aiLoading}>
        {aiLoading ? 'Generating…' : '✦ Generate AI Performance Analysis'}
      </Btn>
      {aiError && <div style={{ color: 'red', fontSize: 12, marginTop: 6 }}>{aiError}</div>}
    </div>
  );

  return (
    <div style={{ fontFamily: 'system-ui', maxWidth: 520, margin: '0 auto', padding: 20 }}>
      <Head><title>Weekly Finance Report</title></Head>
      <h2 style={{ margin: '0 0 3px', fontSize: 19 }}>Weekly Financial Report</h2>
      <p style={{ margin: '0 0 14px', color: '#888', fontSize: 12 }}>Revenue and COGS fields accept inc. GST — ex-GST calculated automatically.</p>

      <Field label="Week Ending (e.g. 06 Apr 2025)" value={weekLabel} onChange={setWeekLabel} prefix="📅" />

      <div style={{ display: 'flex', marginBottom: 16, borderRadius: 7, overflow: 'hidden', border: '1px solid #ddd' }}>
        <TabBtn id="manual" label="✏️ Manual Entry" />
        <TabBtn id="import" label="📂 Import Data" />
      </div>

      {tab === 'import' && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 9, padding: 12, marginBottom: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <div style={{ fontWeight: 700, fontSize: 13 }}>🔵 Xero — Labour Data</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, color: xeroStatus === 'connected' ? '#16a34a' : xeroStatus === 'error' ? '#dc2626' : '#888' }}>
                  {xeroStatus === 'connected' ? '● Connected' : xeroStatus === 'error' ? '● Error' : '○ Not connected'}
                </span>
                {xeroStatus !== 'connected'
                  ? <Btn onClick={() => window.location.href = '/api/xero-auth'} variant="xero" small>Connect Xero</Btn>
                  : <Btn onClick={() => { setXeroStatus('disconnected'); addLog('Xero disconnected'); }} variant="outline" small>Disconnect</Btn>}
              </div>
            </div>
            <div style={{ fontSize: 12, color: '#666', marginBottom: 8 }}>Fetches wages, super and payroll directly from your Xero P&L</div>
            {xeroStatus === 'connected' && (
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div>
                  <label style={{ fontSize: 11, color: '#555', display: 'block', marginBottom: 2 }}>From</label>
                  <input type="date" value={fromDate} onChange={e => setFromDate(e.target.value)} style={{ border: '1px solid #ddd', borderRadius: 5, padding: '5px 8px', fontSize: 13 }} />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: '#555', display: 'block', marginBottom: 2 }}>To</label>
                  <input type="date" value={toDate} onChange={e => setToDate(e.target.value)} style={{ border: '1px solid #ddd', borderRadius: 5, padding: '5px 8px', fontSize: 13 }} />
                </div>
                <Btn onClick={fetchXeroLabour} variant="xero" small disabled={xeroLoading}>{xeroLoading ? 'Fetching…' : 'Fetch Labour'}</Btn>
              </div>
            )}
          </div>

          <div style={{ background: '#f8f9ff', border: '1px solid #dde', borderRadius: 9, padding: 12, marginBottom: 10 }}>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>📊 Lightspeed Excel Report</div>
            <div style={{ fontSize: 12, color: '#666', marginBottom: 8 }}>Imports Turnover (Coffee and Food) and Transactions</div>
            <input ref={lsRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: 'none' }} onChange={e => handleLightspeed(e.target.files)} />
            <Btn onClick={() => lsRef.current.click()} variant="outline" small>Upload Lightspeed Export</Btn>
          </div>

          <div style={{ background: '#fff8f0', border: '1px solid #f0d8b0', borderRadius: 9, padding: 12, marginBottom: 10 }}>
            <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>🧾 Supplier Invoices (PDF)</div>
            <div style={{ fontSize: 12, color: '#666', marginBottom: 8 }}>
              Auto-recognises: <b>Stel, Norkatu</b> (Coffee) · <b>Moco, Fresho, Big Michaels, Coca-Cola, Ordermentum</b> (Food)
            </div>
            <input ref={pdfRef} type="file" accept="application/pdf" multiple style={{ display: 'none' }} onChange={e => handlePDFs(Array.from(e.target.files))} />
            <Btn onClick={() => pdfRef.current.click()} variant="outline" small disabled={parsing}>{parsing ? 'Reading PDFs…' : 'Upload Invoice PDFs'}</Btn>
            {invoices.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#555', marginBottom: 4 }}>Parsed Invoices:</div>
                {invoices.map((inv, i) => (
                  <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, padding: '4px 0', borderBottom: '1px solid #f0e0c8' }}>
                    <span>{inv.supplier || inv.file}</span>
                    <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      {fmt(inv.total_inc_gst || 0)}
                      {inv.category ? <Tag color={inv.category === 'coffee' ? '#7c3aed' : '#16a34a'}>{inv.category}</Tag> : <Tag color="#dc2626">⚠ uncat</Tag>}
                    </span>
                  </div>
                ))}
                {invoiceUncat.length > 0 && <div style={{ fontSize: 11, color: '#dc2626', marginTop: 5 }}>⚠ {invoiceUncat.length} invoice(s) need manual categorisation below</div>}
                <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                  <Btn onClick={applyInvoiceToCOGS} variant="green" small>Apply to COGS →</Btn>
                  <Btn onClick={() => setInvoices([])} variant="outline" small>Clear</Btn>
                </div>
              </div>
            )}
          </div>

          {log.length > 0 && (
            <div style={{ background: '#111', color: '#7eff9a', borderRadius: 8, padding: '10px 12px', fontSize: 11, fontFamily: 'monospace', maxHeight: 100, overflowY: 'auto' }}>
              {log.map((l, i) => <div key={i}>{l}</div>)}
            </div>
          )}
        </div>
      )}

      <div style={{ fontWeight: 600, fontSize: 12, color: '#333', margin: '10px 0 6px', textTransform: 'uppercase', letterSpacing: 0.5 }}>Revenue (inc. GST)</div>
      <Field label="Turnover — Coffee (inc. GST)" value={merged.turnoverCoffeeInc} onChange={set('turnoverCoffeeInc')} readOnly={isAuto('turnoverCoffeeInc')} />
      <Field label="Turnover — Food and Bev (inc. GST)" value={merged.turnoverFoodInc} onChange={set('turnoverFoodInc')} readOnly={isAuto('turnoverFoodInc')} />

      <div style={{ fontWeight: 600, fontSize: 12, color: '#333', margin: '10px 0 6px', textTransform: 'uppercase', letterSpacing: 0.5 }}>COGS (inc. GST)</div>
      <Field label="COGS — Coffee (inc. GST)" value={merged.cogsCoffeeInc} onChange={set('cogsCoffeeInc')} readOnly={isAuto('cogsCoffeeInc')} />
      <Field label="COGS — Food and Bev (inc. GST)" value={merged.cogsFoodInc} onChange={set('cogsFoodInc')} readOnly={isAuto('cogsFoodInc')} />

      <div style={{ fontWeight: 600, fontSize: 12, color: '#333', margin: '10px 0 6px', textTransform: 'uppercase', letterSpacing: 0.5 }}>Labour (ex. GST — from Xero)</div>
      <Field label="Labour — Wages, Super and Payroll (ex. GST)" value={merged.labourExGST} onChange={set('labourExGST')} readOnly={isAuto('labourExGST')} />

      <div style={{ fontWeight: 600, fontSize: 12, color: '#333', margin: '10px 0 6px', textTransform: 'uppercase', letterSpacing: 0.5 }}>Transactions</div>
      <Field label="Number of Transactions" value={merged.transactions} onChange={set('transactions')} prefix="#" readOnly={isAuto('transactions')} />

      {Object.keys(autoFields).length > 0 && <div style={{ fontSize: 11, color: '#16a34a', marginBottom: 8 }}>✓ Green fields auto-filled. You can still edit them.</div>}
      <div style={{ marginTop: 14 }}><Btn onClick={() => setStep('report')}>Generate Report →</Btn></div>
    </div>
  );
}
