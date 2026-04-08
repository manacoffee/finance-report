// Calls Claude to generate the AI narrative report
const fmt = n => `$${Number(n).toLocaleString('en-AU', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const pct = (a, b) => b === 0 ? '—' : `${((a / b) * 100).toFixed(1)}%`;

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { weekLabel, coffeeEx, foodEx, total, cogsCoEx, cogsFdEx, totalCOGS, gp, gpPct, labourEx, labourPct, txns, avg } = req.body;

  const prompt = `You are a financial analyst for a café/hospitality business.
Generate a concise, professional weekly financial performance summary based on the following KPIs (all figures exclude GST).

Week: ${weekLabel || 'This week'}

REVENUE
- Turnover Coffee: ${fmt(coffeeEx)} (${pct(coffeeEx, total)} of total)
- Turnover Food & Bev: ${fmt(foodEx)} (${pct(foodEx, total)} of total)
- Total Turnover: ${fmt(total)}

COST OF GOODS SOLD
- COGS Coffee: ${fmt(cogsCoEx)} (${pct(cogsCoEx, coffeeEx)} of Coffee Turnover)
- COGS Food & Bev: ${fmt(cogsFdEx)} (${pct(cogsFdEx, foodEx)} of F&B Turnover)
- Total COGS: ${fmt(totalCOGS)} (${pct(totalCOGS, total)} of Total Turnover)

LABOUR
- Labour Cost: ${fmt(labourEx)} (${labourPct.toFixed(1)}% of turnover)

PERFORMANCE
- Gross Profit: ${fmt(gp)} (${gpPct.toFixed(1)}% margin)
- Transactions: ${Number(txns).toLocaleString()}
- Average Customer Spend (ex-GST): ${fmt(avg)}

Please provide:
1. A 2-3 sentence executive summary
2. Key highlights (positives)
3. Areas of concern or watch points (flag if labour % exceeds 35% or COGS ratios are high)
4. 2-3 actionable recommendations

Keep it practical and hospitality-focused. Use **bold** for section labels only.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }],
      }),
    });
    const data = await response.json();
    const report = data.content?.map(b => b.text || '').join('') || '';
    res.status(200).json({ report });
  } catch (err) {
    console.error('AI report error:', err);
    res.status(500).json({ error: 'Failed to generate report' });
  }
}
