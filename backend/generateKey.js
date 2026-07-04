const crypto = require('crypto');
const os = require('os');

// Machine ka unique identifier
const machineName = os.hostname();
const SECRET_MASTER = 'SEKUVO_MASTER_SECRET_2024';

// Encrypted key generate karo
const encryptedKey = crypto
  .createHmac('sha256', SECRET_MASTER)
  .update(machineName + '_SEKUVO_ADMIN')
  .digest('hex');

// Expiry date — 1 saal baad
const expiresAt = new Date();
expiresAt.setFullYear(expiresAt.getFullYear() + 1);

const keyFile = {
  key: encryptedKey,
  deviceId: 'SEKUVO_' + machineName.toUpperCase(),
  machine: machineName,
  createdAt: new Date().toISOString(),
  expiresAt: expiresAt.toISOString()
};

console.log('=================================');
console.log('Your Sekuvo Key File Content:');
console.log('=================================');
console.log(JSON.stringify(keyFile, null, 2));
console.log('=================================');
console.log('Machine Name:', machineName);
console.log('Copy this to your pendrive as: sekuvo-key.json');