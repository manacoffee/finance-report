const express = require('express');
const axios = require('axios');
const path = require('path');
const { randomUUID } = require('crypto');

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
    const r = await axios.get(
      `https://api.xero.com/api.xro/2.0/Invoices?InvoiceNumbers=${encodeURIComponent(invoiceNumber)}&Type=ACCPAY`,
      { headers: xeroHeaders(token, tenantId) }
    );
    const invoices = r.data.Invoices || [];
    const active = invoices.filter(i => i.Status !== 'VOIDED');
    res.json({ exists: active.length > 0, status: active[0]?.Status || null, invoiceId: active[0]?.InvoiceID || null });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
      { Invoices: [{ Type: 'ACCPAY', Contact: { ContactID: contact.ContactID }, InvoiceNumber: invoiceNumber, Date: invoiceDate, DueDate: dueDate || null, Status: 'DRAFT', LineAmountTypes: 'Exclusive',
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
const MCP_TOOLS = [
  { name: 'check_duplicate_invoice', description: 'Check if an invoice number already exists in Xero. ALWAYS call this before creating a bill. Stel Coffee sends overdue reminder emails so this check is critical.', inputSchema: { type: 'object', properties: { invoice_number: { type: 'string' } }, required: ['invoice_number'] } },
  { name: 'create_xero_bill', description: 'Create a purchase bill in Xero as a DRAFT. Only call after confirming no duplicate with check_duplicate_invoice.', inputSchema: { type: 'object', properties: { supplier_name: { type: 'string' }, invoice_number: { type: 'string' }, invoice_date: { type: 'string', description: 'YYYY-MM-DD' }, due_date: { type: 'string', description: 'YYYY-MM-DD, default net 30' }, line_items: { type: 'array', items: { type: 'object', properties: { description: { type: 'string' }, quantity: { type: 'number', default: 1 }, unit_amount: { type: 'number', description: 'EX-GST amount' }, account_code: { type: 'string', description: 'Coffee/milk=700, Food&Bev=701, General=429' }, tax_type: { type: 'string', default: 'INPUT' } }, required: ['description', 'unit_amount', 'account_code'] } } }, required: ['supplier_name', 'invoice_number', 'invoice_date', 'line_items'] } },
  { name: 'attach_receipt_to_bill', description: 'Attach a PDF receipt to an existing Xero bill', inputSchema: { type: 'object', properties: { bill_id: { type: 'string' }, filename: { type: 'string' }, base64_content: { type: 'string' }, mime_type: { type: 'string', default: 'application/pdf' } }, required: ['bill_id', 'filename', 'base64_content'] } },
  { name: 'get_open_bills', description: 'Get draft and authorised bills from Xero for reconciliation matching.', inputSchema: { type: 'object', properties: { from_date: { type: 'string' }, to_date: { type: 'string' } } } },
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
];

async function executeTool(name, params) {
  const BASE = `http://localhost:${PORT}`;
  switch (name) {
    case 'check_duplicate_invoice': return (await axios.get(`${BASE}/api/xero-check-invoice?invoiceNumber=${encodeURIComponent(params.invoice_number)}`)).data;
    case 'create_xero_bill': return (await axios.post(`${BASE}/api/xero-create-bill`, { supplierName: params.supplier_name, invoiceNumber: params.invoice_number, invoiceDate: params.invoice_date, dueDate: params.due_date, lineItems: (params.line_items || []).map(li => ({ description: li.description, quantity: li.quantity || 1, unitAmount: li.unit_amount, accountCode: li.account_code, taxType: li.tax_type || 'INPUT' })) })).data;
    case 'attach_receipt_to_bill': return (await axios.post(`${BASE}/api/xero-attach-receipt`, { billId: params.bill_id, filename: params.filename, base64Content: params.base64_content, mimeType: params.mime_type || 'application/pdf' })).data;
    case 'get_open_bills': { const qs = new URLSearchParams(); if (params.from_date) qs.set('fromDate', params.from_date); if (params.to_date) qs.set('toDate', params.to_date); return (await axios.get(`${BASE}/api/xero-open-bills?${qs}`)).data; }
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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mana Coffee server running on port ${PORT}`));
