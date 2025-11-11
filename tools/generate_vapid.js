// Usage: node tools/generate_vapid.js
// Generates VAPID key pair using web-push and prints Base64 URL-safe public/private keys.
try {
  const webpush = require('web-push');
  const keys = webpush.generateVAPIDKeys();
  // keys are already URL-safe base64 strings
  console.log('VAPID_PUBLIC_KEY=' + keys.publicKey);
  console.log('VAPID_PRIVATE_KEY=' + keys.privateKey);
  console.log('\nSet these in your Render dashboard as VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY.');
} catch (e) {
  console.error('Please install web-push: npm install web-push');
  console.error(e && e.message ? e.message : e);
}
