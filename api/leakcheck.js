const { leakcheck, clientIp, respond } = require('../lib/hibp');
module.exports = (req, res) => {
  const account = new URL(req.url, 'http://x').searchParams.get('account');
  return respond(res, () => leakcheck(account, clientIp(req)), 'leakcheck');
};
