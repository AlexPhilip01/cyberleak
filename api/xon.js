const { xon, clientIp, respond } = require('../lib/hibp');
module.exports = (req, res) => {
  const account = new URL(req.url, 'http://x').searchParams.get('account');
  return respond(res, () => xon(account, clientIp(req)), 'xon');
};
