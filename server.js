const express = require('express');
const axios = require('axios');
const path = require('path');
const { randomUUID } = require('crypto');
const pdf = require('pdf-parse');

const app = express();
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let xeroStore = {
  accessToken: null,
  refreshToken: process.env.XERO_REFRESH_TOKEN || null,
  tenantId: process.env.XERO_TENANT_ID || null,
  expiresAt: 0,
};

let gmailStore = {
  accessToken: null,
  refreshToken: process.env.GMAIL_REFRESH_TOKEN || null,
  expiresAt: 0,
};

const mcpSessions = new Map();

async function getValidToken() {
  if (xeroStore.accessToken && Date.now() < xeroStore.expiresAt - 60_000) {
    return { token: xeroStore.accessToken, tenantId: xeroStore.tenantId };
  }
  if (!xeroStore.refreshToken) {
    throw new Error('Not connected to Xero — please visit /api/xero-auth to reconnect');
  }
  const r = await axios.post(
    'https://identity.xero.com/connect/token',
    new URLSearchParams({ grant_type: 'refresh_token', refresh_token: xeroStore.refreshToken }),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(
          `${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`
        ).toString('base64')}`,
      },
    }
  );
  xeroStore.accessToken = r.data.access_token;
  xeroStore.refreshToken = r.data.refresh_token;
  xeroStore.expiresAt = Date.now() + r.data.expires_in * 1_000;
  return { token: xeroStore.accessToken, tenantId: xeroStore.tenantId };
}

async function getValidGmailToken() {
  if (gmailStore.accessToken && Date.now() < gmailStore.expiresAt - 60_000) {
    return gmailStore.accessToken;
  }
  if (!gmailStore.refreshToken) {
    throw new Error('Not connected to Gmail — please visit /api/gmail-auth to connect');
  }
  const r = await axios.post(
    'https://oauth2.googleapis.com/token',
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: gmailStore.refreshToken,
      client_id: process.env.GMAIL_CLIENT_ID,
      client_secret: process.env.GMAIL_CLIENT_SECRET,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  gmailStore.accessToken = r.data.access_token;
  // Google only returns a new refresh_token occasionally; keep the old one if not returned
  if (r.data.refresh_token) gmailStore.refreshToken = r.data.refresh_token;
  gmailStore.expiresAt = Date.now() + r.data.expires_in * 1_000;
  return gmailStore.accessToken;
}

function gmailHeaders(token) {
  return { Authorization: `Bearer ${token}`, Accept: 'application/json' };
}

// Decode a base64url string into a Buffer. Gmail API returns attachment data
// and raw message bodies in base64url encoding (RFC 4648 §5).
function base64urlDecode(str) {
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64');
}

function xeroHeaders(token, tenantId) {
  return {
    Authorization: `Bearer ${token}`,
    'xero-tenant-id': tenantId,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '').split('; ').filter(Boolean).map(c => {
      const [k, ...v] = c.split('=');
      return [k, v.join('=')];
    })
  );
}

app.get('/api/xero-auth', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.XERO_CLIENT_ID,
    redirect_uri: process.env.XERO_REDIRECT_URI,
    scope: 'openid profile email offline_access accounting.invoices accounting.contacts accounting.banktransactions accounting.settings.read accounting.reports.profitandloss.read accounting.attachments',
    state: 'finance_report',
  });
  res.redirect(`https://login.xero.com/identity/connect/authorize?${params}`);
});

app.get('/api/xero-callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?xero=error');
  try {
    const tokenRes = await axios.post(
      'https://identity.xero.com/connect/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.XERO_REDIRECT_URI,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(
            `${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`
          ).toString('base64')}`,
        },
      }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    const tenantsRes = await axios.get('https://api.xero.com/connections', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const tenantId = tenantsRes.data[0]?.tenantId;
    if (!tenantId) throw new Error('No Xero organisation found');
    xeroStore = {
      accessToken: access_token,
      refreshToken: refresh_token,
      tenantId,
      expiresAt: Date.now() + expires_in * 1_000,
    };
    const maxAge = 60 * 60 * 24 * 30;
    res.setHeader('Set-Cookie', [
      `xero_access_token=${access_token}; HttpOnly; Path=/; Max-Age=${expires_in}; SameSite=Lax`,
      `xero_refresh_token=${refresh_token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`,
      `xero_tenant_id=${tenantId}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`,
    ]);
    res.redirect('/?xero=connected');
  } catch (err) {
    console.error('Xero callback error:', err.response?.data || err.message);
    res.redirect('/?xero=error');
  }
});

// ─── Gmail OAuth ──────────────────────────────────────────────────────────
// Full OAuth 2.0 flow for `brisbane@manacoffee.net`. Used to fetch PDF
// invoice attachments server-side so Claude doesn't have to pass them
// through the MCP tool as base64.
app.get('/api/gmail-auth', (req, res) => {
  if (!process.env.GMAIL_CLIENT_ID || !process.env.GMAIL_REDIRECT_URI) {
    return res.status(500).send('Gmail OAuth not configured — GMAIL_CLIENT_ID / GMAIL_REDIRECT_URI env vars missing.');
  }
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.GMAIL_CLIENT_ID,
    redirect_uri: process.env.GMAIL_REDIRECT_URI,
    scope: 'https://www.googleapis.com/auth/gmail.readonly',
    access_type: 'offline',
    prompt: 'consent',         // force refresh_token issuance
    include_granted_scopes: 'true',
    state: 'finance_report',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/gmail-callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?gmail=error');
  try {
    const tokenRes = await axios.post(
      'https://oauth2.googleapis.com/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.GMAIL_CLIENT_ID,
        client_secret: process.env.GMAIL_CLIENT_SECRET,
        redirect_uri: process.env.GMAIL_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = tokenRes.data;
    if (!refresh_token) {
      // Google only returns refresh_token when prompt=consent AND the user has
      // not previously granted this scope. If missing, re-consent is required.
      console.error('Gmail callback: no refresh_token returned. Revoke the app at https://myaccount.google.com/permissions and re-authorise.');
      return res.redirect('/?gmail=error&reason=no_refresh_token');
    }
    gmailStore = {
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: Date.now() + expires_in * 1_000,
    };
    res.redirect('/?gmail=connected');
  } catch (err) {
    console.error('Gmail callback error:', err.response?.data || err.message);
    res.redirect('/?gmail=error');
  }
});

app.get('/api/xero-labour', async (req, res) => {
  const { fromDate, toDate } = req.query;
  if (!fromDate || !toDate) return res.status(400).json({ error: 'fromDate and toDate required' });
  const cookies = parseCookies(req);
  let accessToken = cookies.xero_access_token;
  const refreshToken = cookies.xero_refresh_token;
  const tenantId = cookies.xero_tenant_id;
  if (!tenantId || !refreshToken) return res.status(401).json({ error: 'Not connected to Xero' });
  if (!accessToken) {
    try {
      const r = await axios.post(
        'https://identity.xero.com/connect/token',
        new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: `Basic ${Buffer.from(
              `${process.env.XERO_CLIENT_ID}:${process.env.XERO_CLIENT_SECRET}`
            ).toString('base64')}`,
          },
        }
      );
      accessToken = r.data.access_token;
      res.setHeader('Set-Cookie', [
        `xero_access_token=${accessToken}; HttpOnly; Path=/; Max-Age=${r.data.expires_in}; SameSite=Lax`,
        `xero_refresh_token=${r.data.refresh_token}; HttpOnly; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax`,
      ]);
    } catch {
      return res.status(401).json({ error: 'Xero session expired — please reconnect' });
    }
  }
  try {
    const LABOUR_KEYWORDS = ['wage', 'labour', 'labor', 'payroll', 'salary', 'salaries', 'superannuation', 'super'];
    const plRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss?fromDate=${fromDate}&toDate=${toDate}&standardLayout=true`,
      { headers: { Authorization: `Bearer ${accessToken}`, 'xero-tenant-id': tenantId, Accept: 'application/json' } }
    );
    const rows = plRes.data?.Reports?.[0]?.Rows || [];
    let labourExGST = 0;
    const walk = rows => {
      for (const row of rows) {
        if (row.Rows) walk(row.Rows);
        if (row.Cells) {
          const name = (row.Cells[0]?.Value || '').toLowerCase();
          const amt = parseFloat(row.Cells[1]?.Value) || 0;
          if (LABOUR_KEYWORDS.some(k => name.includes(k))) labourExGST += Math.abs(amt);
        }
      }
    };
    walk(rows);
    res.json({ labourExGST: parseFloat(labourExGST.toFixed(2)) });
  } catch (err) {
    console.error('Xero P&L error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch Xero data' });
  }
});

app.post('/api/parse-invoice', async (req, res) => {
  const { base64, filename } = req.body;
  if (!base64) return res.status(400).json({ error: 'No file data' });
  const SUPPLIERS = {
    stel: 'coffee', norkatu: 'coffee', moco: 'food', fresho: 'food',
    'big michaels': 'food', 'coca cola': 'food', 'coca-cola': 'food', ordermentum: 'food',
  };
  const categFromSupplier = name => {
    const l = (name || '').toLowerCase();
    for (const [k, v] of Object.entries(SUPPLIERS)) if (l.includes(k)) return v;
    return null;
  };
  try {
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: [
          { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } },
          { type: 'text', text: 'Extract from this invoice and respond ONLY with valid JSON, no markdown:\n{"supplier":"<n>","invoice_number":"<inv#>","invoice_date":"<date>","total_inc_gst":<number>,"total_ex_gst":<number>,"gst_amount":<number>}\nUse null for missing fields.' },
        ]}],
      },
      { headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }
    );
    const text = response.data.content?.map(b => b.text || '').join('') || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    res.json({ ...parsed, category: categFromSupplier(parsed.supplier), file: filename });
  } catch (err) {
    console.error('Invoice parse error:', err.message);
    res.status(500).json({ error: 'Failed to parse invoice' });
  }
});

app.post('/api/extract-pdf-text', async (req, res) => {
  try {
    const result = await extractPdfTextFromGmail(req.body);
    res.json(result);
  } catch (err) {
    console.error('extract-pdf-text error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || err.message });
  }
});

app.post('/api/extract-email-body', async (req, res) => {
  try {
    const result = await extractEmailBodyFromGmail(req.body);
    res.json(result);
  } catch (err) {
    console.error('extract-email-body error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || err.message });
  }
});

app.post('/api/generate-report', async (req, res) => {
  const { weekLabel, coffeeEx, foodEx, total, cogsCoEx, cogsFdEx, totalCOGS, gp, gpPct, labourEx, labourPct, txns, avg } = req.body;
  const fmt = n => `$${Number(n).toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  const pct = (a, b) => b === 0 ? '—' : `${((a / b) * 100).toFixed(1)}%`;
  const prompt = `You are a financial analyst for a café. Generate a concise weekly report.
Week: ${weekLabel || 'This week'}
Turnover Coffee: ${fmt(coffeeEx)}, Food & Bev: ${fmt(foodEx)}, Total: ${fmt(total)}
COGS Coffee: ${fmt(cogsCoEx)} (${pct(cogsCoEx, coffeeEx)}), Food: ${fmt(cogsFdEx)} (${pct(cogsFdEx, foodEx)})
Labour: ${fmt(labourEx)} (${Number(labourPct).toFixed(1)}% of turnover)
Gross Profit: ${fmt(gp)} (${Number(gpPct).toFixed(1)}%), Transactions: ${Number(txns).toLocaleString()}, Avg Spend: ${fmt(avg)}
Provide: 1) 2-sentence executive summary 2) Key highlights 3) Watch points (flag labour >35% or high COGS) 4) 2-3 recommendations. Use **bold** for section labels.`;
  try {
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      { model: 'claude-sonnet-4-20250514', max_tokens: 1000, messages: [{ role: 'user', content: prompt }] },
      { headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' } }
    );
    res.json({ report: response.data.content?.map(b => b.text || '').join('') || '' });
  } catch (err) {
    console.error('AI error:', err.message);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

app.get('/api/xero-check-invoice', async (req, res) => {
  console.log('═══ CHECK INVOICE REQUEST ═══');
  console.log('Invoice number:', req.query.invoiceNumber);
  const { invoiceNumber } = req.query;
  if (!invoiceNumber) return res.status(400).json({ error: 'invoiceNumber required' });
  try {
    const { token, tenantId } = await getValidToken();

    // 1. Check purchase bills (ACCPAY invoices)
    const billsRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Invoices?InvoiceNumbers=${encodeURIComponent(invoiceNumber)}&Type=ACCPAY`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const invoices = billsRes.data.Invoices || [];
    const activeBills = invoices.filter(i => i.Status !== 'VOIDED');
    const bill = activeBills[0] || null;

    // 2. Check Spend Money bank transactions by Reference field
    const spendWhere = `Type=="SPEND" AND Reference!=null AND Reference.Contains("${String(invoiceNumber).replace(/"/g, '\\"')}")`;
    const spendRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/BankTransactions?where=${encodeURIComponent(spendWhere)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const spendTxs = (spendRes.data.BankTransactions || []).filter(t => t.Status !== 'DELETED' && t.Status !== 'VOIDED');
    const spend = spendTxs[0] || null;

    const existsAsBill = !!bill;
    const existsAsSpendMoney = !!spend;

    res.json({
      // Legacy shape — kept for backwards compatibility
      exists: existsAsBill || existsAsSpendMoney,
      status: bill?.Status || spend?.Status || null,
      invoiceId: bill?.InvoiceID || null,
      // Expanded shape
      existsAsBill,
      bill: bill ? { invoiceId: bill.InvoiceID, status: bill.Status, total: bill.Total, date: bill.Date, contact: bill.Contact?.Name } : null,
      existsAsSpendMoney,
      spendMoney: spend ? { bankTransactionId: spend.BankTransactionID, status: spend.Status, total: spend.Total, date: spend.Date, reference: spend.Reference, contact: spend.Contact?.Name } : null,
      spendMoneyMatches: spendTxs.length,
    });
  } catch (err) {
    console.error('═══ CHECK INVOICE ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('═══════════════════════════');
    res.status(500).json({ error: err.response?.data?.Message || err.message });
  }
});

app.get('/api/xero-search-spend-money', async (req, res) => {
  console.log('═══ SEARCH SPEND MONEY REQUEST ═══');
  console.log(JSON.stringify(req.query, null, 2));
  const { reference, contactName, amount, fromDate, toDate, bankAccountCode } = req.query;
  if (!reference && !contactName && !amount && !fromDate && !toDate) {
    return res.status(400).json({ error: 'At least one of reference, contactName, amount, fromDate, or toDate is required' });
  }
  try {
    const { token, tenantId } = await getValidToken();

    const clauses = ['Type=="SPEND"'];
    if (reference) {
      const safe = String(reference).replace(/"/g, '\\"');
      clauses.push(`Reference!=null AND Reference.Contains("${safe}")`);
    }
    if (contactName) {
      const safe = String(contactName).replace(/"/g, '\\"');
      clauses.push(`Contact.Name.Contains("${safe}")`);
    }
    if (fromDate) {
      const [y, m, d] = String(fromDate).split('-').map(Number);
      if (y && m && d) clauses.push(`Date>=DateTime(${y},${m},${d})`);
    }
    if (toDate) {
      const [y, m, d] = String(toDate).split('-').map(Number);
      if (y && m && d) clauses.push(`Date<=DateTime(${y},${m},${d})`);
    }
    const where = clauses.join(' AND ');
    const r = await axios.get(
      `https://api.xero.com/api.xro/2.0/BankTransactions?where=${encodeURIComponent(where)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    let txs = (r.data.BankTransactions || []).filter(t => t.Status !== 'DELETED' && t.Status !== 'VOIDED');

    // Amount filter applied in-memory because Xero's where clause for BankTransaction Total is flaky
    if (amount) {
      const target = Number(amount);
      if (!Number.isNaN(target)) {
        txs = txs.filter(t => Math.abs(Number(t.Total) - target) < 0.02);
      }
    }

    // Optional bank account filter (in-memory)
    if (bankAccountCode) {
      txs = txs.filter(t => t.BankAccount?.Code === String(bankAccountCode));
    }

    res.json({
      count: txs.length,
      transactions: txs.map(t => ({
        bankTransactionId: t.BankTransactionID,
        date: t.Date,
        status: t.Status,
        total: t.Total,
        reference: t.Reference,
        contact: t.Contact?.Name,
        bankAccountCode: t.BankAccount?.Code,
        bankAccountName: t.BankAccount?.Name,
      })),
    });
  } catch (err) {
    console.error('═══ SEARCH SPEND MONEY ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('════════════════════════════════');
    res.status(500).json({ error: err.response?.data?.Message || err.message });
  }
});

app.post('/api/xero-create-bill', async (req, res) => {
  console.log('═══ CREATE BILL REQUEST ═══');
  console.log(JSON.stringify(req.body, null, 2));
  console.log('════════════════════════════');
  const { supplierName, invoiceNumber, invoiceDate, dueDate, lineItems } = req.body;
  if (!supplierName || !invoiceNumber || !invoiceDate || !lineItems?.length) {
    return res.status(400).json({ error: 'supplierName, invoiceNumber, invoiceDate, and lineItems are required' });
  }
  try {
    const { token, tenantId } = await getValidToken();
    const contactRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(supplierName)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const contact = contactRes.data.Contacts?.[0];
    if (!contact) return res.status(404).json({ error: `Supplier "${supplierName}" not found in Xero contacts.` });
    const r = await axios.post(
      'https://api.xero.com/api.xro/2.0/Invoices',
      { Invoices: [{ Type: 'ACCPAY', Contact: { ContactID: contact.ContactID }, InvoiceNumber: invoiceNumber, Date: invoiceDate, DueDate: dueDate || null, Status: 'AUTHORISED', LineAmountTypes: 'Exclusive',
        LineItems: lineItems.map(li => ({ Description: li.description, Quantity: Number(li.quantity) || 1, UnitAmount: Number(li.unitAmount), AccountCode: String(li.accountCode), TaxType: li.taxType || 'INPUT' })) }] },
      { headers: xeroHeaders(token, tenantId) }
    );
    const created = r.data.Invoices?.[0];
    res.json({ success: true, invoiceId: created?.InvoiceID, invoiceNumber: created?.InvoiceNumber, status: created?.Status, total: created?.Total });
} catch (err) {
    console.error('═══ CREATE BILL ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('═════════════════════════');
    res.status(500).json({ 
      error: err.response?.data?.Message || err.message,
      xeroResponse: err.response?.data,
      xeroStatus: err.response?.status 
    });
  }
});

app.post('/api/xero-attach-receipt', async (req, res) => {
  const { billId, filename, base64Content, mimeType } = req.body;
  if (!billId || !filename || !base64Content) return res.status(400).json({ error: 'billId, filename, and base64Content are required' });
  try {
    const { token, tenantId } = await getValidToken();
    const buffer = Buffer.from(base64Content, 'base64');
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/Invoices/${billId}/Attachments/${encodeURIComponent(filename)}`,
      buffer,
      { headers: { Authorization: `Bearer ${token}`, 'xero-tenant-id': tenantId, 'Content-Type': mimeType || 'application/pdf', 'Content-Length': buffer.length }, maxBodyLength: Infinity, maxContentLength: Infinity }
    );
    res.json({ success: true, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.Message || err.message });
  }
});

app.get('/api/xero-open-bills', async (req, res) => {
  const { fromDate, toDate } = req.query;
  try {
    const { token, tenantId } = await getValidToken();
    let url = 'https://api.xero.com/api.xro/2.0/Invoices?Type=ACCPAY&Statuses=DRAFT,SUBMITTED,AUTHORISED';
    if (fromDate) url += `&fromDate=${fromDate}`;
    if (toDate) url += `&toDate=${toDate}`;
    const r = await axios.get(url, { headers: xeroHeaders(token, tenantId) });
    res.json({ bills: r.data.Invoices || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/xero-create-spend-money', async (req, res) => {
  console.log('═══ CREATE SPEND MONEY REQUEST ═══');
  console.log(JSON.stringify(req.body, null, 2));
  console.log('══════════════════════════════════');
  const { payeeName, transactionDate, reference, bankAccountCode, lineItems } = req.body;
  if (!payeeName || !transactionDate || !lineItems?.length) {
    return res.status(400).json({ error: 'payeeName, transactionDate, and lineItems are required' });
  }
  try {
    const { token, tenantId } = await getValidToken();

    const contactRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(payeeName)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    let contact = contactRes.data.Contacts?.[0];
    if (!contact) {
      const newContactRes = await axios.post(
        'https://api.xero.com/api.xro/2.0/Contacts',
        { Contacts: [{ Name: payeeName }] },
        { headers: xeroHeaders(token, tenantId) }
      );
      contact = newContactRes.data.Contacts?.[0];
    }

    const code = String(bankAccountCode || '605');
    const acctRes = await axios.get(
      `https://api.xero.com/api.xro/2.0/Accounts?where=${encodeURIComponent(`Code=="${code}"`)}`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const bankAccount = acctRes.data.Accounts?.[0];
    if (!bankAccount) return res.status(404).json({ error: `Bank account with code ${code} not found` });

    const r = await axios.post(
      'https://api.xero.com/api.xro/2.0/BankTransactions',
      { BankTransactions: [{
        Type: 'SPEND',
        Contact: { ContactID: contact.ContactID },
        BankAccount: { AccountID: bankAccount.AccountID },
        Date: transactionDate,
        Reference: reference || null,
        Status: 'AUTHORISED',
        LineAmountTypes: 'Exclusive',
        LineItems: lineItems.map(li => ({
          Description: li.description,
          Quantity: Number(li.quantity) || 1,
          UnitAmount: Number(li.unitAmount),
          AccountCode: String(li.accountCode),
          TaxType: li.taxType || 'INPUT',
        })),
      }] },
      { headers: xeroHeaders(token, tenantId) }
    );
    const created = r.data.BankTransactions?.[0];
    res.json({
      success: true,
      bankTransactionId: created?.BankTransactionID,
      status: created?.Status,
      total: created?.Total,
      contactId: contact.ContactID,
    });
  } catch (err) {
    console.error('═══ CREATE SPEND MONEY ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('════════════════════════════════');
    res.status(500).json({
      error: err.response?.data?.Message || err.message,
      xeroResponse: err.response?.data,
      xeroStatus: err.response?.status,
    });
  }
});

app.post('/api/xero-attach-receipt-spend-money', async (req, res) => {
  const { bankTransactionId, filename, base64Content, mimeType } = req.body;
  if (!bankTransactionId || !filename || !base64Content) {
    return res.status(400).json({ error: 'bankTransactionId, filename, and base64Content are required' });
  }
  try {
    const { token, tenantId } = await getValidToken();
    const buffer = Buffer.from(base64Content, 'base64');
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/BankTransactions/${bankTransactionId}/Attachments/${encodeURIComponent(filename)}`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'xero-tenant-id': tenantId,
          'Content-Type': mimeType || 'application/pdf',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );
    res.json({ success: true, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.Message || err.message });
  }
});

app.post('/api/xero-update-bill', async (req, res) => {
  console.log('═══ UPDATE BILL REQUEST ═══');
  console.log(JSON.stringify(req.body, null, 2));
  console.log('═══════════════════════════');
  const { invoiceId, supplierName, invoiceDate, dueDate, reference, status } = req.body;
  if (!invoiceId) return res.status(400).json({ error: 'invoiceId required' });
  if (!supplierName && !invoiceDate && !dueDate && reference === undefined && !status) {
    return res.status(400).json({ error: 'At least one field to update required: supplierName, invoiceDate, dueDate, reference, or status' });
  }
  try {
    const { token, tenantId } = await getValidToken();

    // Build partial-update payload — only include fields that were provided
    const updated = { InvoiceID: invoiceId };

    if (supplierName) {
      const contactRes = await axios.get(
        `https://api.xero.com/api.xro/2.0/Contacts?searchTerm=${encodeURIComponent(supplierName)}`,
        { headers: xeroHeaders(token, tenantId) }
      );
      const contact = contactRes.data.Contacts?.[0];
      if (!contact) return res.status(404).json({ error: `Supplier "${supplierName}" not found in Xero contacts.` });
      updated.Contact = { ContactID: contact.ContactID };
    }
    if (invoiceDate) updated.Date = invoiceDate;
    if (dueDate) updated.DueDate = dueDate;
    if (reference !== undefined) updated.Reference = reference;
    if (status) updated.Status = status;

    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/Invoices/${invoiceId}`,
      { Invoices: [updated] },
      { headers: xeroHeaders(token, tenantId) }
    );
    const result = r.data.Invoices?.[0];
    res.json({
      success: true,
      invoiceId: result?.InvoiceID,
      invoiceNumber: result?.InvoiceNumber,
      status: result?.Status,
      total: result?.Total,
      contact: result?.Contact?.Name,
      date: result?.Date,
      dueDate: result?.DueDate,
      reference: result?.Reference,
    });
  } catch (err) {
    console.error('═══ UPDATE BILL ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('═════════════════════════');
    res.status(500).json({
      error: err.response?.data?.Message || err.message,
      xeroResponse: err.response?.data,
      xeroStatus: err.response?.status,
    });
  }
});

// ─── Gmail helpers (server-side only) ────────────────────────────────────
// Find Gmail label ID by display name (e.g. "Supplier invoices").
async function resolveGmailLabelId(labelName) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    'https://gmail.googleapis.com/gmail/v1/users/me/labels',
    { headers: gmailHeaders(token) }
  );
  const match = (r.data.labels || []).find(l => l.name === labelName);
  if (!match) throw new Error(`Gmail label "${labelName}" not found`);
  return match.id;
}

// Walk a Gmail message payload tree to collect attachments.
function collectAttachments(payload, out = []) {
  if (!payload) return out;
  if (payload.filename && payload.body && payload.body.attachmentId) {
    out.push({
      filename: payload.filename,
      mimeType: payload.mimeType,
      size: payload.body.size || 0,
      attachmentId: payload.body.attachmentId,
      partId: payload.partId || null,
    });
  }
  if (Array.isArray(payload.parts)) {
    payload.parts.forEach(p => collectAttachments(p, out));
  }
  return out;
}

function pickHeader(headers, name) {
  const h = (headers || []).find(x => (x.name || '').toLowerCase() === name.toLowerCase());
  return h ? h.value : null;
}

// ─── Gmail API routes ────────────────────────────────────────────────────
// List messages under a Gmail label, with attachment metadata. Designed so
// Claude can ask "what's unprocessed in 'Supplier invoices'?" each Monday.
app.get('/api/gmail-list-by-label', async (req, res) => {
  const { label, maxResults } = req.query;
  if (!label) return res.status(400).json({ error: 'label query param required (e.g. "Supplier invoices")' });
  try {
    const token = await getValidGmailToken();
    const labelId = await resolveGmailLabelId(label);
    const listRes = await axios.get(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages?labelIds=${encodeURIComponent(labelId)}&maxResults=${Number(maxResults) || 50}`,
      { headers: gmailHeaders(token) }
    );
    const ids = (listRes.data.messages || []).map(m => m.id);
    // Fetch each message in parallel — metadata format is lightweight.
    const messages = await Promise.all(ids.map(async id => {
      const m = await axios.get(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`,
        { headers: gmailHeaders(token) }
      );
      const p = m.data.payload || {};
      const headers = p.headers || [];
      return {
        messageId: m.data.id,
        threadId: m.data.threadId,
        subject: pickHeader(headers, 'Subject'),
        from: pickHeader(headers, 'From'),
        to: pickHeader(headers, 'To'),
        date: pickHeader(headers, 'Date'),
        internalDate: m.data.internalDate,
        snippet: m.data.snippet,
        attachments: collectAttachments(p),
      };
    }));
    res.json({ label, count: messages.length, messages });
  } catch (err) {
    console.error('═══ GMAIL LIST BY LABEL ERROR ═══');
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    console.error('═════════════════════════════════');
    res.status(500).json({ error: err.response?.data?.error?.message || err.message });
  }
});

// Fetch the raw PDF bytes of a Gmail attachment, attach to a Xero bill.
// Claude only passes small IDs — the heavy lifting happens server-side.
async function fetchGmailAttachment(messageId, attachmentId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.data) throw new Error('Gmail attachment returned empty data');
  return base64urlDecode(r.data.data);
}

async function fetchGmailRawMessage(messageId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.raw) throw new Error('Gmail raw message returned empty data');
  return base64urlDecode(r.data.raw);
}

// Fetch a Gmail PDF attachment server-side and extract its text via pdf-parse.
// Used to read Net/GST figures and line items from Moco, Big Michael's, CCA,
// Stel, Norkatu invoice PDFs without passing bytes through the MCP connection.
async function extractPdfTextFromGmail({ messageId, attachmentId, maxChars = 50000 }) {
  if (!messageId || !attachmentId) {
    throw new Error('messageId and attachmentId are required');
  }
  const buffer = await fetchGmailAttachment(messageId, attachmentId);
  const parsed = await pdf(buffer);
  const effectiveMax = Number(maxChars) > 0 ? Number(maxChars) : 50000;
  const text = parsed.text.length > effectiveMax
    ? parsed.text.slice(0, effectiveMax) + '\n[...truncated]'
    : parsed.text;
  return {
    messageId,
    attachmentId,
    pageCount: parsed.numpages,
    bytes: buffer.length,
    charsReturned: text.length,
    text,
  };
}

// Fetch a full Gmail message (headers + payload tree). Used by
// extractEmailBodyFromGmail to walk MIME parts. Uses format=full rather than
// format=raw so the API pre-parses the MIME structure for us.
async function fetchGmailFullMessage(messageId) {
  const token = await getValidGmailToken();
  const r = await axios.get(
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
    { headers: gmailHeaders(token) }
  );
  if (!r.data.payload) throw new Error('Gmail full message returned empty payload');
  return r.data;
}

// Minimal HTML-to-text conversion for email bodies. Sufficient for parsing
// supplier invoice emails (CCA, etc.) where we just need the readable text.
// Not a general-purpose HTML parser — don't feed it arbitrary web pages.
function stripHtml(html) {
  return html
    // Remove script/style blocks entirely
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    // Inject newlines for block-level elements so text doesn't mash together
    .replace(/<\/(p|div|li|h[1-6]|tr|table)>/gi, '\n')
    .replace(/<br\s*\/?>/gi, '\n')
    // Strip remaining tags
    .replace(/<[^>]+>/g, '')
    // Decode common named HTML entities
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&hellip;/gi, '…')
    // Decode numeric HTML entities (decimal and hex)
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    // Collapse whitespace without destroying intentional line breaks
    .replace(/[ \t]+/g, ' ')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// Fetch a Gmail message server-side and return its body text. Prefers
// text/plain MIME parts; falls back to stripping HTML from text/html if plain
// text is absent. Used for supplier invoices where data lives in the email
// body rather than a PDF attachment (e.g. Coca-Cola CCEP Non-Stock Invoice).
// Decodes all parts as UTF-8 — if a supplier sends in a different charset,
// mojibake is the failure mode and we'd need charset-aware decoding.
async function extractEmailBodyFromGmail({ messageId, maxChars = 50000 }) {
  if (!messageId) throw new Error('messageId is required');

  const message = await fetchGmailFullMessage(messageId);

  // Walk the MIME tree, collecting text/plain and text/html leaf parts.
  const collected = { plain: [], html: [] };
  function walk(part) {
    if (!part) return;
    if (part.mimeType === 'text/plain' && part.body?.data) {
      collected.plain.push(base64urlDecode(part.body.data).toString('utf8'));
    } else if (part.mimeType === 'text/html' && part.body?.data) {
      collected.html.push(base64urlDecode(part.body.data).toString('utf8'));
    }
    if (Array.isArray(part.parts)) {
      for (const child of part.parts) walk(child);
    }
  }
  walk(message.payload);

  let bodySource = 'plain';
  let body = collected.plain.join('\n\n').trim();
  if (!body && collected.html.length > 0) {
    bodySource = 'html';
    body = stripHtml(collected.html.join('\n\n')).trim();
  }
  if (!body) bodySource = null; // no text body found

  // Surface useful headers so the caller doesn't need a separate metadata call.
  const headers = message.payload?.headers || [];
  const getHeader = name =>
    headers.find(h => h.name?.toLowerCase() === name.toLowerCase())?.value || null;

  const effectiveMax = Number(maxChars) > 0 ? Number(maxChars) : 50000;
  const text = body.length > effectiveMax
    ? body.slice(0, effectiveMax) + '\n[...truncated]'
    : body;

  return {
    messageId,
    subject: getHeader('Subject'),
    from: getHeader('From'),
    date: getHeader('Date'),
    bodySource, // 'plain' | 'html' | null
    charsReturned: text.length,
    text,
  };
}

app.post('/api/xero-attach-gmail-pdf-to-bill', async (req, res) => {
  console.log('═══ ATTACH GMAIL PDF TO BILL ═══');
  console.log(JSON.stringify(req.body, null, 2));
  const { billId, gmailMessageId, gmailAttachmentId, filename, mimeType } = req.body;
  if (!billId || !gmailMessageId || !gmailAttachmentId || !filename) {
    return res.status(400).json({ error: 'billId, gmailMessageId, gmailAttachmentId, filename are required' });
  }
  try {
    const buffer = await fetchGmailAttachment(gmailMessageId, gmailAttachmentId);
    const { token, tenantId } = await getValidToken();
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/Invoices/${billId}/Attachments/${encodeURIComponent(filename)}`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'xero-tenant-id': tenantId,
          'Content-Type': mimeType || 'application/pdf',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );
    res.json({ success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    res.status(500).json({ error: err.response?.data?.Message || err.response?.data?.error?.message || err.message });
  }
});

app.post('/api/xero-attach-gmail-pdf-to-spend-money', async (req, res) => {
  console.log('═══ ATTACH GMAIL PDF TO SPEND MONEY ═══');
  console.log(JSON.stringify(req.body, null, 2));
  const { bankTransactionId, gmailMessageId, gmailAttachmentId, filename, mimeType } = req.body;
  if (!bankTransactionId || !gmailMessageId || !gmailAttachmentId || !filename) {
    return res.status(400).json({ error: 'bankTransactionId, gmailMessageId, gmailAttachmentId, filename are required' });
  }
  try {
    const buffer = await fetchGmailAttachment(gmailMessageId, gmailAttachmentId);
    const { token, tenantId } = await getValidToken();
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/BankTransactions/${bankTransactionId}/Attachments/${encodeURIComponent(filename)}`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'xero-tenant-id': tenantId,
          'Content-Type': mimeType || 'application/pdf',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );
    res.json({ success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    res.status(500).json({ error: err.response?.data?.Message || err.response?.data?.error?.message || err.message });
  }
});

// Stel (and any other email-only supplier) has no PDF — the email body IS
// the invoice. Attach the raw message as .eml instead.
app.post('/api/xero-attach-gmail-email-to-bill', async (req, res) => {
  console.log('═══ ATTACH GMAIL EMAIL TO BILL ═══');
  console.log(JSON.stringify(req.body, null, 2));
  const { billId, gmailMessageId, filename } = req.body;
  if (!billId || !gmailMessageId) {
    return res.status(400).json({ error: 'billId and gmailMessageId are required' });
  }
  try {
    const buffer = await fetchGmailRawMessage(gmailMessageId);
    const { token, tenantId } = await getValidToken();
    const name = filename || `email-${gmailMessageId}.eml`;
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/Invoices/${billId}/Attachments/${encodeURIComponent(name)}`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'xero-tenant-id': tenantId,
          'Content-Type': 'message/rfc822',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );
    res.json({ success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    res.status(500).json({ error: err.response?.data?.Message || err.response?.data?.error?.message || err.message });
  }
});

app.post('/api/xero-attach-gmail-email-to-spend-money', async (req, res) => {
  console.log('═══ ATTACH GMAIL EMAIL TO SPEND MONEY ═══');
  console.log(JSON.stringify(req.body, null, 2));
  const { bankTransactionId, gmailMessageId, filename } = req.body;
  if (!bankTransactionId || !gmailMessageId) {
    return res.status(400).json({ error: 'bankTransactionId and gmailMessageId are required' });
  }
  try {
    const buffer = await fetchGmailRawMessage(gmailMessageId);
    const { token, tenantId } = await getValidToken();
    const name = filename || `email-${gmailMessageId}.eml`;
    const r = await axios.post(
      `https://api.xero.com/api.xro/2.0/BankTransactions/${bankTransactionId}/Attachments/${encodeURIComponent(name)}`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'xero-tenant-id': tenantId,
          'Content-Type': 'message/rfc822',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      }
    );
    res.json({ success: true, bytesAttached: buffer.length, attachment: r.data.Attachments?.[0] });
  } catch (err) {
    console.error('Status:', err.response?.status);
    console.error('Data:', JSON.stringify(err.response?.data, null, 2));
    console.error('Message:', err.message);
    res.status(500).json({ error: err.response?.data?.Message || err.response?.data?.error?.message || err.message });
  }
});

const MCP_TOOLS = [
  { name: 'check_duplicate_invoice', description: 'Check if an invoice number already exists in Xero — searches BOTH purchase bills (ACCPAY) AND Spend Money bank transactions (by Reference field). ALWAYS call this before creating a bill. Returns { existsAsBill, existsAsSpendMoney, bill, spendMoney, ... }. Stel Coffee sends overdue reminder emails so this check is critical. Note: Spend Money match depends on the invoice number being stored in the Reference field — for legacy entries that may not have a reference, use search_spend_money with contactName + amount as a cross-check.', inputSchema: { type: 'object', properties: { invoice_number: { type: 'string' } }, required: ['invoice_number'] } },
  { name: 'create_xero_bill', description: 'Create a purchase bill in Xero as AUTHORISED. Only call after confirming no duplicate with check_duplicate_invoice.', inputSchema: { type: 'object', properties: { supplier_name: { type: 'string' }, invoice_number: { type: 'string' }, invoice_date: { type: 'string', description: 'YYYY-MM-DD' }, due_date: { type: 'string', description: 'YYYY-MM-DD, default net 30' }, line_items: { type: 'array', items: { type: 'object', properties: { description: { type: 'string' }, quantity: { type: 'number', default: 1 }, unit_amount: { type: 'number', description: 'EX-GST amount' }, account_code: { type: 'string', description: 'Coffee/milk=700, Food&Bev=701, General=429' }, tax_type: { type: 'string', default: 'INPUT' } }, required: ['description', 'unit_amount', 'account_code'] } } }, required: ['supplier_name', 'invoice_number', 'invoice_date', 'line_items'] } },
  {
    name: 'update_xero_bill',
    description: 'Update an existing purchase bill (ACCPAY) in Xero. Use when a bill needs its contact, dates, reference, or status changed after creation — e.g. when a supplier contact has been renamed, a due date was wrong, or to move a DRAFT to AUTHORISED. Does NOT update line items (delete and recreate instead for line item changes). Only fields provided are modified; other fields remain untouched. At least one updatable field must be provided.',
    inputSchema: {
      type: 'object',
      properties: {
        invoice_id: { type: 'string', description: 'The Xero InvoiceID (UUID) of the bill to update. Obtainable from create_xero_bill responses or check_duplicate_invoice.' },
        supplier_name: { type: 'string', description: 'Optional — change the contact on the bill. Supplier must already exist in Xero contacts (search is by first match).' },
        invoice_date: { type: 'string', description: 'Optional — new invoice Date in YYYY-MM-DD format.' },
        due_date: { type: 'string', description: 'Optional — new DueDate in YYYY-MM-DD format.' },
        reference: { type: 'string', description: 'Optional — set or change the Reference field. Pass empty string "" to clear.' },
        status: { type: 'string', description: 'Optional — change status. Valid transitions: DRAFT → SUBMITTED → AUTHORISED, or DELETED to void a draft.' },
      },
      required: ['invoice_id'],
    },
  },
  { name: 'attach_receipt_to_bill', description: 'Attach a PDF receipt to an existing Xero bill', inputSchema: { type: 'object', properties: { bill_id: { type: 'string' }, filename: { type: 'string' }, base64_content: { type: 'string' }, mime_type: { type: 'string', default: 'application/pdf' } }, required: ['bill_id', 'filename', 'base64_content'] } },
  { name: 'get_open_bills', description: 'Get draft and authorised bills from Xero for reconciliation matching.', inputSchema: { type: 'object', properties: { from_date: { type: 'string' }, to_date: { type: 'string' } } } },
  {
    name: 'search_spend_money',
    description: 'Search existing Spend Money (SPEND) bank transactions in Xero by any combination of reference, contact name, amount, and date range. Use this to catch duplicates for invoices that were previously entered as Spend Money rather than bills — especially legacy entries where the invoice number may not be in the Reference field (in which case, match on contact_name + amount + date range). At least one filter is required.',
    inputSchema: {
      type: 'object',
      properties: {
        reference: { type: 'string', description: 'Substring to match against the Reference field (case-sensitive). E.g. invoice number.' },
        contact_name: { type: 'string', description: 'Substring to match against the Contact name. E.g. "Stel Coffee", "Norkatu".' },
        amount: { type: 'number', description: 'Exact transaction total (inc GST) to match, ±$0.01.' },
        from_date: { type: 'string', description: 'YYYY-MM-DD, inclusive' },
        to_date: { type: 'string', description: 'YYYY-MM-DD, inclusive' },
        bank_account_code: { type: 'string', description: 'Optional — filter by bank account code e.g. 605.' },
      },
    },
  },
  {
    name: 'create_spend_money',
    description: 'Create an AUTHORISED Spend Money transaction in Xero for purchases already paid by card/bank. Use for receipt photos (Bunnings, Woolworths, fuel etc). Defaults to bank account code 605 (Business Trans Acct).',
    inputSchema: {
      type: 'object',
      properties: {
        payee_name: { type: 'string', description: 'Merchant name from receipt. Auto-created as contact if not existing.' },
        transaction_date: { type: 'string', description: 'YYYY-MM-DD' },
        reference: { type: 'string', description: 'Optional reference, e.g. receipt number' },
        bank_account_code: { type: 'string', description: 'Bank account code. Default 605. Others: 602 Tyro, 603 Cash Float, 778 Petty Cash.', default: '605' },
        line_items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              description: { type: 'string' },
              quantity: { type: 'number', default: 1 },
              unit_amount: { type: 'number', description: 'EX-GST amount' },
              account_code: { type: 'string', description: 'Bunnings/Officeworks=429, Woolworths/Coles=702, liquor=701, fuel=999, uniforms=508, cleaning=408, repairs=473, cafes=470' },
              tax_type: { type: 'string', default: 'INPUT' },
            },
            required: ['description', 'unit_amount', 'account_code'],
          },
        },
      },
      required: ['payee_name', 'transaction_date', 'line_items'],
    },
  },
  {
    name: 'attach_receipt_to_spend_money',
    description: 'Attach a receipt (PDF or image) to an existing Xero Spend Money transaction.',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string' },
        filename: { type: 'string' },
        base64_content: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bank_transaction_id', 'filename', 'base64_content'],
    },
  },
  {
    name: 'list_supplier_invoice_emails',
    description: 'List Gmail messages under a specified label, with attachment metadata. Designed for the Monday weekly workflow: fetch everything in the "Supplier invoices" label to find unprocessed Moco, Big Michael\'s, and Coca-Cola invoices. Returns messageId + attachmentId for each attachment — use those IDs with attach_gmail_pdf_to_bill / attach_gmail_pdf_to_spend_money. The tool does NOT mark messages as processed; use check_duplicate_invoice on each invoice number to see if it\'s already in Xero.',
    inputSchema: {
      type: 'object',
      properties: {
        label: { type: 'string', description: 'Gmail label display name, e.g. "Supplier invoices".' },
        max_results: { type: 'number', description: 'Max messages to return (default 50).' },
      },
      required: ['label'],
    },
  },
  {
    name: 'attach_gmail_pdf_to_bill',
    description: 'Attach a PDF from a Gmail message directly to a Xero bill. Railway fetches the attachment server-side — no base64 over MCP — so this works for large PDFs. Use after creating a bill for a supplier whose invoice arrived via Gmail as a PDF attachment.',
    inputSchema: {
      type: 'object',
      properties: {
        bill_id: { type: 'string', description: 'Xero InvoiceID (UUID) of the bill.' },
        gmail_message_id: { type: 'string', description: 'Gmail message ID containing the attachment.' },
        gmail_attachment_id: { type: 'string', description: 'Gmail attachmentId — get this from list_supplier_invoice_emails.' },
        filename: { type: 'string', description: 'Filename to use in Xero (e.g. "invoice-4217654.pdf").' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bill_id', 'gmail_message_id', 'gmail_attachment_id', 'filename'],
    },
  },
  {
    name: 'attach_gmail_pdf_to_spend_money',
    description: 'Attach a PDF from a Gmail message directly to a Xero Spend Money transaction. Railway fetches the attachment server-side. Standard path for Moco, Big Michael\'s, Coca-Cola invoices.',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string', description: 'Xero BankTransactionID (UUID) of the Spend Money txn.' },
        gmail_message_id: { type: 'string' },
        gmail_attachment_id: { type: 'string' },
        filename: { type: 'string' },
        mime_type: { type: 'string', default: 'application/pdf' },
      },
      required: ['bank_transaction_id', 'gmail_message_id', 'gmail_attachment_id', 'filename'],
    },
  },
  {
    name: 'attach_gmail_email_to_bill',
    description: 'Attach the raw Gmail message (as .eml) to a Xero bill. Use when the invoice has no PDF attachment and the email body IS the invoice — e.g. Stel Coffee emails from MYOB PayDirect, which have line items in the body but no PDF.',
    inputSchema: {
      type: 'object',
      properties: {
        bill_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        filename: { type: 'string', description: 'Optional. Defaults to "email-<messageId>.eml".' },
      },
      required: ['bill_id', 'gmail_message_id'],
    },
  },
  {
    name: 'attach_gmail_email_to_spend_money',
    description: 'Attach the raw Gmail message (as .eml) to a Xero Spend Money transaction. Use for email-only invoices paid on card.',
    inputSchema: {
      type: 'object',
      properties: {
        bank_transaction_id: { type: 'string' },
        gmail_message_id: { type: 'string' },
        filename: { type: 'string' },
      },
      required: ['bank_transaction_id', 'gmail_message_id'],
    },
  },
  {
    name: 'extract_gmail_pdf_text',
    description: 'Fetch a Gmail PDF attachment server-side, extract its text via pdf-parse, and return the text. Use for supplier invoices where data lives in the PDF (Moco Net/GST figures, Big Michael\'s line items, CCA totals, Norkatu). Get message_id + attachment_id from list_supplier_invoice_emails. Safe for large PDFs — bytes never leave Railway.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string', description: 'Gmail message ID containing the PDF attachment.' },
        attachment_id: { type: 'string', description: 'Gmail attachmentId (from list_supplier_invoice_emails).' },
        max_chars: { type: 'number', description: 'Max characters of extracted text to return. Defaults to 50000.' },
      },
      required: ['message_id', 'attachment_id'],
    },
  },
  {
    name: 'extract_gmail_email_body',
    description: 'Fetch a Gmail message server-side and return its body text. Prefers text/plain MIME part; falls back to stripping HTML from text/html if plain text is absent. Use for supplier invoices where invoice data lives in the email body rather than a PDF attachment (e.g. Coca-Cola CCEP Non-Stock Invoice emails from aus.coke.credit@ccamatil.com). Get message_id from list_supplier_invoice_emails. No new OAuth scopes needed — uses the same gmail.readonly scope as extract_gmail_pdf_text.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string', description: 'Gmail message ID.' },
        max_chars: { type: 'number', description: 'Max characters of body text to return. Defaults to 50000.' },
      },
      required: ['message_id'],
    },
  },
];

async function executeTool(name, params) {
  const BASE = `http://localhost:${PORT}`;
  switch (name) {
    case 'check_duplicate_invoice': return (await axios.get(`${BASE}/api/xero-check-invoice?invoiceNumber=${encodeURIComponent(params.invoice_number)}`)).data;
    case 'create_xero_bill': return (await axios.post(`${BASE}/api/xero-create-bill`, { supplierName: params.supplier_name, invoiceNumber: params.invoice_number, invoiceDate: params.invoice_date, dueDate: params.due_date, lineItems: (params.line_items || []).map(li => ({ description: li.description, quantity: li.quantity || 1, unitAmount: li.unit_amount, accountCode: li.account_code, taxType: li.tax_type || 'INPUT' })) })).data;
    case 'update_xero_bill':
      return (await axios.post(`${BASE}/api/xero-update-bill`, {
        invoiceId: params.invoice_id,
        supplierName: params.supplier_name,
        invoiceDate: params.invoice_date,
        dueDate: params.due_date,
        reference: params.reference,
        status: params.status,
      })).data;
    case 'attach_receipt_to_bill': return (await axios.post(`${BASE}/api/xero-attach-receipt`, { billId: params.bill_id, filename: params.filename, base64Content: params.base64_content, mimeType: params.mime_type || 'application/pdf' })).data;
    case 'get_open_bills': { const qs = new URLSearchParams(); if (params.from_date) qs.set('fromDate', params.from_date); if (params.to_date) qs.set('toDate', params.to_date); return (await axios.get(`${BASE}/api/xero-open-bills?${qs}`)).data; }
    case 'search_spend_money': {
      const qs = new URLSearchParams();
      if (params.reference) qs.set('reference', params.reference);
      if (params.contact_name) qs.set('contactName', params.contact_name);
      if (params.amount !== undefined && params.amount !== null) qs.set('amount', String(params.amount));
      if (params.from_date) qs.set('fromDate', params.from_date);
      if (params.to_date) qs.set('toDate', params.to_date);
      if (params.bank_account_code) qs.set('bankAccountCode', params.bank_account_code);
      return (await axios.get(`${BASE}/api/xero-search-spend-money?${qs}`)).data;
    }
    case 'create_spend_money':
      return (await axios.post(`${BASE}/api/xero-create-spend-money`, {
        payeeName: params.payee_name,
        transactionDate: params.transaction_date,
        reference: params.reference,
        bankAccountCode: params.bank_account_code || '605',
        lineItems: (params.line_items || []).map(li => ({
          description: li.description,
          quantity: li.quantity || 1,
          unitAmount: li.unit_amount,
          accountCode: li.account_code,
          taxType: li.tax_type || 'INPUT',
        })),
      })).data;
    case 'attach_receipt_to_spend_money':
      return (await axios.post(`${BASE}/api/xero-attach-receipt-spend-money`, {
        bankTransactionId: params.bank_transaction_id,
        filename: params.filename,
        base64Content: params.base64_content,
        mimeType: params.mime_type || 'application/pdf',
      })).data;
    case 'list_supplier_invoice_emails': {
      const qs = new URLSearchParams();
      qs.set('label', params.label);
      if (params.max_results) qs.set('maxResults', String(params.max_results));
      return (await axios.get(`${BASE}/api/gmail-list-by-label?${qs}`)).data;
    }
    case 'attach_gmail_pdf_to_bill':
      return (await axios.post(`${BASE}/api/xero-attach-gmail-pdf-to-bill`, {
        billId: params.bill_id,
        gmailMessageId: params.gmail_message_id,
        gmailAttachmentId: params.gmail_attachment_id,
        filename: params.filename,
        mimeType: params.mime_type || 'application/pdf',
      })).data;
    case 'attach_gmail_pdf_to_spend_money':
      return (await axios.post(`${BASE}/api/xero-attach-gmail-pdf-to-spend-money`, {
        bankTransactionId: params.bank_transaction_id,
        gmailMessageId: params.gmail_message_id,
        gmailAttachmentId: params.gmail_attachment_id,
        filename: params.filename,
        mimeType: params.mime_type || 'application/pdf',
      })).data;
    case 'attach_gmail_email_to_bill':
      return (await axios.post(`${BASE}/api/xero-attach-gmail-email-to-bill`, {
        billId: params.bill_id,
        gmailMessageId: params.gmail_message_id,
        filename: params.filename,
      })).data;
    case 'attach_gmail_email_to_spend_money':
      return (await axios.post(`${BASE}/api/xero-attach-gmail-email-to-spend-money`, {
        bankTransactionId: params.bank_transaction_id,
        gmailMessageId: params.gmail_message_id,
        filename: params.filename,
      })).data;
    case 'extract_gmail_pdf_text':
      return await extractPdfTextFromGmail({
        messageId: params.message_id,
        attachmentId: params.attachment_id,
        maxChars: params.max_chars,
      });
    case 'extract_gmail_email_body':
      return await extractEmailBodyFromGmail({
        messageId: params.message_id,
        maxChars: params.max_chars,
      });
    default: throw new Error(`Unknown tool: ${name}`);
  }
}

function sendToSession(sessionId, data) {
  const res = mcpSessions.get(sessionId);
  if (res && !res.writableEnded) res.write(`data: ${JSON.stringify(data)}\n\n`);
}

app.get('/sse', (req, res) => {
  const sessionId = randomUUID();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();
  mcpSessions.set(sessionId, res);
  console.log(`MCP session opened: ${sessionId}`);
  res.write(`event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`);
  const ping = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); else clearInterval(ping); }, 30_000);
  req.on('close', () => { mcpSessions.delete(sessionId); clearInterval(ping); console.log(`MCP session closed: ${sessionId}`); });
});

app.post('/messages', async (req, res) => {
  const { sessionId } = req.query;
  const message = req.body;
  res.status(202).json({ status: 'accepted' });
  try {
    const { method, id, params } = message;
    if (method === 'initialize') {
      sendToSession(sessionId, { jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'mana-coffee-xero', version: '1.0.0' } } });
    } else if (method === 'notifications/initialized') {
      return;
    } else if (method === 'tools/list') {
      sendToSession(sessionId, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    } else if (method === 'tools/call') {
      const { name, arguments: args } = params;
      console.log(`MCP tool call: ${name}`);
      try {
        const result = await executeTool(name, args);
        sendToSession(sessionId, { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] } });
      } catch (toolErr) {
        sendToSession(sessionId, { jsonrpc: '2.0', id, error: { code: -32603, message: toolErr.message } });
      }
    } else {
      sendToSession(sessionId, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  } catch (err) {
    sendToSession(sessionId, { jsonrpc: '2.0', id: req.body?.id, error: { code: -32603, message: err.message } });
  }
});

app.options('/messages', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(204);
});

app.get('/api/debug', (req, res) => {
  res.json({
    clientIdLength: (process.env.XERO_CLIENT_ID || '').length,
    clientIdStart: (process.env.XERO_CLIENT_ID || '').slice(0, 4),
    redirectUri: process.env.XERO_REDIRECT_URI,
    hasSecret: !!process.env.XERO_CLIENT_SECRET,
    hasStoredRefreshToken: !!xeroStore.refreshToken,
    tenantId: xeroStore.tenantId,
    gmail: {
      clientIdConfigured: !!process.env.GMAIL_CLIENT_ID,
      clientSecretConfigured: !!process.env.GMAIL_CLIENT_SECRET,
      redirectUri: process.env.GMAIL_REDIRECT_URI || null,
      hasStoredRefreshToken: !!gmailStore.refreshToken,
    },
  });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mana Coffee server running on port ${PORT}`));
