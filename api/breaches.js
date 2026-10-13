const { breaches, respond } = require('../lib/hibp');
module.exports = (req, res) => respond(res, () => breaches(), 'breaches');
