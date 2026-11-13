// AgentAvow: send Google Ads spend to the admin dashboard, once a day.
//
// Runs inside Google Ads (Tools -> Bulk actions -> Scripts), scheduled Daily. Reads
// the last 7 complete days (the account's time zone, today left out) per ad group for
// every campaign whose name starts with "2026-", and POSTs them to AgentAvow. Each
// day + campaign + ad group replaces what the dashboard already holds, so sending the
// same 7 days every night picks up Google's late adjustments and never double counts.
//
// The token below is the AD_SPEND_INGEST_TOKEN from the server's .env.secrets. Paste
// it in place of PASTE_TOKEN_HERE inside Google Ads only; never commit it anywhere.

const TOKEN = 'PASTE_TOKEN_HERE';

const ENDPOINT = 'https://agentavow.com/api/v1/admin/ad-spend/ingest';
const CAMPAIGN_PREFIX = '2026-';

function main() {
  if (!TOKEN || TOKEN === 'PASTE_TOKEN_HERE') {
    throw new Error('Paste the AD_SPEND_INGEST_TOKEN into the TOKEN line first.');
  }

  // LAST_7_DAYS is the 7 days before today, so every day in it is complete.
  const query =
    'SELECT segments.date, campaign.name, ad_group.name, ' +
    'metrics.cost_micros, metrics.impressions, metrics.clicks ' +
    'FROM ad_group ' +
    "WHERE segments.date DURING LAST_7_DAYS AND campaign.name LIKE '" +
    CAMPAIGN_PREFIX + "%'";

  const rows = [];
  const it = AdsApp.report(query).rows();
  while (it.hasNext()) {
    const r = it.next();
    rows.push({
      day: r['segments.date'], // YYYY-MM-DD
      campaign: r['campaign.name'],
      ad_group: r['ad_group.name'],
      // Micros to dollars, two decimals, sent as a string so nothing is lost to floats.
      cost: (Number(r['metrics.cost_micros']) / 1e6).toFixed(2),
      impressions: Number(r['metrics.impressions']),
      clicks: Number(r['metrics.clicks']),
    });
  }

  if (!rows.length) {
    Logger.log('No ad group rows in the last 7 days for campaigns starting "' +
               CAMPAIGN_PREFIX + '". Nothing sent.');
    return;
  }

  const response = UrlFetchApp.fetch(ENDPOINT, {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-Ad-Spend-Token': TOKEN },
    payload: JSON.stringify({ channel: 'google', rows: rows }),
    muteHttpExceptions: true,
  });

  const code = response.getResponseCode();
  // Never log the token or the request headers; the response body holds no secret.
  Logger.log('Sent ' + rows.length + ' rows. AgentAvow answered ' + code + ': ' +
             response.getContentText().slice(0, 500));
  if (code !== 200) {
    // A failed run shows in Google Ads' script history, and Google can email on it.
    throw new Error('AgentAvow ingest failed with HTTP ' + code + '.');
  }
}
