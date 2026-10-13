const { range, respond } = require('../../lib/hibp');
module.exports = (req, res) => {
  const prefix = (req.query && req.query.prefix) || new URL(req.url, 'http://x').pathname.split('/').pop();
  return respond(res, () => range(prefix), 'range');
};
