const crypto = require('crypto');
const hash = crypto.createHash('md5').update('data').digest('hex');
const hash2 = crypto.createHash('sha1').update('data').digest('hex');
