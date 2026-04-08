// Uses Claude AI to extract invoice data from uploaded PDFs
export const config = { api: { bodyParser: { sizeLimit: '10mb' } } };

const SUPPLIERS = {
  stel: 'coffee', norkatu: 'coffee',
  moco: 'food', fresho: 'food', 'big michaels': 'food',
  'coca cola': 'food', 'coca-cola': 'food', ordermentum: 'food',
};

function categFromSupplier(name) {
  const l = (name || '').toLowerCase();
  for (const [k, v] of Object.entries(SUPPLIERS)) {
    if (l.includes(k)) return v;
  }
  return null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { base64, filename } = req.body;
  if (!base64) return res.status(400).json({ error: 'No file data provided' });

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
        messages: [{
          role: 'user',
          content: [
            {
              type: 'document',
              source: { type: 'base64', media_type: 'application/pdf', data: base64 },
            },
            {
              type: 'text',
              text: `Extract from this invoice and respond ONLY with valid JSON, no markdown:
{"supplier":"<name>","invoice_number":"<inv#>","invoice_date":"<date>","total_inc_gst":<number>,"total_ex_gst":<number>,"gst_amount":<number>}
Use null for any field you cannot find. Total must be the grand total of the invoice.`,
            },
          ],
        }],
      }),
    });

    const data = await response.json();
    const text = data.content?.map(b => b.text || '').join('') || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());
    const category = categFromSupplier(parsed.supplier);

    res.status(200).json({ ...parsed, category, file: filename });
  } catch (err) {
    console.error('Invoice parse error:', err);
    res.status(500).json({ error: 'Failed to parse invoice' });
  }
}
