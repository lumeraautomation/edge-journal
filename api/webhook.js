const https = require('https');

// Verify Stripe webhook signature
function verifyStripeSignature(payload, sigHeader, secret) {
  const crypto = require('crypto');
  const parts = sigHeader.split(',');
  const timestamp = parts.find(p => p.startsWith('t=')).split('=')[1];
  const sig = parts.find(p => p.startsWith('v1=')).split('=')[1];
  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac('sha256', secret).update(signedPayload).digest('hex');
  return expected === sig;
}

// Find Firebase UID by email using Admin REST API
async function getUIDByEmail(email) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');

  // Create JWT for Firebase Admin
  const jwt = await createJWT(clientEmail, privateKey);
  const token = await getAccessToken(jwt);

  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
      body: JSON.stringify({ email: [email] })
    }
  );
  const data = await res.json();
  const users = data.users;
  if (!users || users.length === 0) return null;
  return users[0].localId;
}

// Set pro_users/{uid} in Firestore
async function setProUser(uid) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');

  const jwt = await createJWT(clientEmail, privateKey);
  const token = await getAccessToken(jwt);

  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/pro_users/${uid}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({
      fields: {
        active: { booleanValue: true },
        activatedAt: { stringValue: new Date().toISOString() }
      }
    })
  });
  return res.ok;
}

// Remove pro access when subscription cancelled/unpaid
async function removeProUser(uid) {
  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');

  const jwt = await createJWT(clientEmail, privateKey);
  const token = await getAccessToken(jwt);

  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/pro_users/${uid}`;
  await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify({
      fields: {
        active: { booleanValue: false },
        cancelledAt: { stringValue: new Date().toISOString() }
      }
    })
  });
}

// Create signed JWT for Google API auth
async function createJWT(clientEmail, privateKey) {
  const crypto = require('crypto');
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: clientEmail, scope: 'https://www.googleapis.com/auth/cloud-platform', aud: 'https://oauth2.googleapis.com/token', exp: now + 3600, iat: now
  })).toString('base64url');
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(`${header}.${payload}`);
  const sig = sign.sign(privateKey, 'base64url');
  return `${header}.${payload}.${sig}`;
}

async function getAccessToken(jwt) {
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  const data = await res.json();
  return data.access_token;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  // Get raw body for signature verification
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks).toString('utf8');

  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  // Verify the request is really from Stripe
  try {
    if (!verifyStripeSignature(rawBody, sig, webhookSecret)) {
      return res.status(400).json({ error: 'Invalid signature' });
    }
  } catch (e) {
    return res.status(400).json({ error: 'Signature error' });
  }

  const event = JSON.parse(rawBody);
  console.log('Stripe event:', event.type);

  try {
    if (event.type === 'checkout.session.completed') {
      const email = event.data.object.customer_details?.email;
      if (!email) return res.status(200).json({ received: true });
      const uid = await getUIDByEmail(email);
      if (uid) {
        await setProUser(uid);
        console.log(`Pro activated for ${email} (${uid})`);
      } else {
        console.log(`No Firebase user found for ${email}`);
      }
    }

    if (event.type === 'customer.subscription.deleted' || event.type === 'invoice.payment_failed') {
      const email = event.data.object.customer_email || event.data.object.customer_details?.email;
      if (email) {
        const uid = await getUIDByEmail(email);
        if (uid) {
          await removeProUser(uid);
          console.log(`Pro removed for ${email} (${uid})`);
        }
      }
    }

    res.status(200).json({ received: true });
  } catch (e) {
    console.error('Webhook error:', e.message);
    res.status(500).json({ error: e.message });
  }
};
