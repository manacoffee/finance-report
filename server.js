const express = require('express');
const axios = require('axios');
const path = require('path');
const { randomUUID } = require('crypto');

const app = express();
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
    'https://identity.xero.com/connect/toke
