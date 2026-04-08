// Fetches labour costs (wages, super, payroll) from Xero P&L for a given date range
import axios from 'axios';

const LABOUR_KEYWORDS = ['wage', 'labour', 'labor', 'payroll', 'salary', 'salaries', 'superannuation', 'super annuation'];

function isLabourAccount(name) {
  const l = (name || '').toLowerCase();
  return LABOUR_KEYWORDS.some(k => l.includes(k));
}

async function refreshAccessToken(refreshToken) {
  const res = await axios.post(
    'https://identity.xero.com/connect/token',
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
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
  return res.data;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).end();

  const { fromDate, toDate } = req.query;
  if (!fromDate || !toDate) return res.status(400).json({ error: 'fromDate and toDate required (YYYY-MM-DD)' });

  // Parse cookies
  const cookies = Object.fromEntries(
    (req.headers.cookie || '').split('; ').map(c => {
      const [k, ...v] = c.split('=');
      return [k, v.join('=')];
    })
  );

  let accessToken = cookies.xero_access_token;
  const refreshToken = cookies.xero_refresh_token;
  const tenantId = cookies.xero_tenant_id;

  if (!tenantId || !refreshToken) {
    return res.status(401).json({ error: 'Not connected to Xero' });
  }

  // Refresh token if access token missing or expired
  if (!accessToken) {
    try {
      const refreshed = await refreshAccessToken(refreshToken);
      accessToken = refreshed.access_token;
      res.setHeader('Set-Cookie', [
        `xero_access_token=${accessToken}; HttpOnly; Path=/; Max-Age=${refreshed.expires_in}; SameSite=Lax`,
        `xero_refresh_token=${refreshed.refresh_token}; HttpOnly; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax`,
      ]);
    } catch {
      return res.status(401).json({ error: 'Xero session expired — please reconnect' });
    }
  }

  try {
    // Fetch P&L from Xero for the given week
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

    // Walk through all P&L rows and sum labour accounts
    const walkRows = (rows) => {
      for (const row of rows) {
        if (row.Rows) walkRows(row.Rows);
        if (row.Cells) {
          const accountName = row.Cells[0]?.Value || '';
          const amount = parseFloat(row.Cells[1]?.Value) || 0;
          if (isLabourAccount(accountName)) {
            labourExGST += Math.abs(amount);
          }
        }
      }
    };
    walkRows(rows);

    res.status(200).json({ labourExGST: parseFloat(labourExGST.toFixed(2)) });
  } catch (err) {
    console.error('Xero P&L error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch Xero data' });
  }
}
