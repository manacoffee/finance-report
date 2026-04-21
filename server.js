const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---- Xero OAuth ----
app.get('/api/xero-auth', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.XERO_CLIENT_ID,
    redirect_uri: process.env.XERO_REDIRECT_URI,
    scope: 'openid profile email offline_access accounting.invoices accounting.reports.profitandloss.read accounting.attachments',
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

  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split('; ').filter(Boolean).map(c => {
      const [k, ...v] = c.split('='); return [k, v.join('=')];
    })
  );
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
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'xero-tenant-id': tenantId,
          Accept: 'application/json',
        },
      }
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
    stel: 'coffee', norkatu: 'coffee',
    moco: 'food', fresho: 'food', 'big michaels': 'food',
    'coca cola': 'food', 'coca-cola': 'food', ordermentum: 'food',
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
        messages: [{
          role: 'user',
          content: [
            { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } },
            { type: 'text', text: 'Extract from this invoice and respond ONLY with valid JSON, no markdown:\n{"supplier":"<n>","invoice_number":"<inv#>","invoice_date":"<date>","total_inc_gst":<number>,"total_ex_gst":<number>,"gst_amount":<number>}\nUse null for missing fields.' },
          ],
        }],
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
      }
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
      {
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
      }
    );
    res.json({ report: response.data.content?.map(b => b.text || '').join('') || '' });
  } catch (err) {
    console.error('AI error:', err.message);
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
