// Xero sends the user back here after they log in
// We exchange the code for an access token and store it in a cookie
import axios from 'axios';

export default async function handler(req, res) {
  const { code, error } = req.query;

  if (error || !code) {
    return res.redirect('/?xero=error');
  }

  try {
    // Exchange the auth code for tokens
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

    // Get the tenant (organisation) ID
    const tenantsRes = await axios.get('https://api.xero.com/connections', {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const tenantId = tenantsRes.data[0]?.tenantId;
    if (!tenantId) throw new Error('No Xero organisation found');

    // Store tokens in cookies (httpOnly for security)
    const maxAge = 60 * 60 * 24 * 30; // 30 days
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
}
