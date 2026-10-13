const { health, respond } = require('../lib/hibp');
module.exports = (req, res) => respond(res, () => health(), 'health');
