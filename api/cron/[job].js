import { runFunction } from '../server.js';

const JOBS = {
  'daily-summary': 'sendDailySummaryEmail',
  'weekly-summary': 'sendWeeklySummaryEmail',
  'monthly-summary': 'sendMonthlySummaryEmail',
  'overdue-loans': 'sendOverdueLoansAlert',
  'pending-approvals': 'sendPendingApprovalsReminder'
};

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ success: false, message: 'Method not allowed.' });
  }

  const secret = String(process.env.CRON_SECRET || '').trim();
  const authorization = String(req.headers.authorization || '');

  if (!secret) {
    return res.status(500).json({ success: false, message: 'CRON_SECRET is not configured.' });
  }

  if (authorization !== `Bearer ${secret}`) {
    return res.status(401).json({ success: false, message: 'Unauthorized cron request.' });
  }

  const job = String(req.query?.job || '').trim();
  const functionName = JOBS[job];

  if (!functionName) {
    return res.status(404).json({ success: false, message: 'Unknown Brightlife cron job.' });
  }

  try {
    const result = await runFunction(functionName, {});
    return res.status(result?.success === false ? 500 : 200).json(result || { success: true });
  } catch (error) {
    console.error('Brightlife cron error:', error);
    return res.status(500).json({ success: false, message: error.message || 'Cron job failed.' });
  }
}
