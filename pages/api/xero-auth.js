// Redirects the user to Xero's login page
export default function handler(req, res) {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.XERO_CLIENT_ID,
    redirect_uri: process.env.XERO_REDIRECT_URI,
    scope: 'openid profile email accounting.reports.read offline_access',
    state: 'finance_report',
  });

  const xeroAuthUrl = `https://login.xero.com/identity/connect/authorize?${params}`;
  res.redirect(xeroAuthUrl);
}
