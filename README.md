# ETH Authenticator package for Node Express

This package works as a middleware for an Express app.

## Exmaple

Refer this repository for an example setup, including a working demo server: https://github.com/pelith/node-Eauth-server.

## Setup

```bash
npm install express-eauth
```

## Usage

Insert it as a middleware to authenticating routes in your Express app. After this middleware, the context object is stored as `req.eauth`, which has attributes listed inside callback functions.

```js
const express = require('express');
const Eauth = require('express-eauth');

let eauthMiddleware = new Eauth({
  // all options and their default values
  signature: 'Signature',
  message: 'Message',
  address: 'Address',
  banner: 'Eauth',
});

const app = express();

/* --- Step 1: authentication request --- */
app.get('/auth/:Address', eauthMiddleware, (req, res) => { 
  //           ^^^^^^^^ the URL parameter

  /* req.eauth
   *   message: The challenge string.
   */
});

/* --- Step 2: challenge response --- */
app.get('/auth/:Message/:Signature', eauthMiddleware, (req, res) => { 
  /*
   * req.eauth
   *   recoveredAddress: The recovered wallet address for the signature.
   */
});
```

### Workflow

1. The client emits an *authentication request*.
2. The server stores and responds with a challenge string.
3. The client prompts and signs a message (challenge, banner) for a user, and send the *challenge response* to the server.
4. The server looks up that challenge string, and matches the corresponding address against the one recovered from the signature. Respond the client with the result.
5. The authentication is now done.

### Options

* `signature='Signature'`
* `message='Message'`
* `address='Address'` \
  These options specify the corresponding URL parameter (in URL, not in query string!) for a request.

* `banner='Eauth'`:`String` \
  An identifier for your app that is sent to the user when an authentication request is made. The user signs the challenge string along with the banner to prevent spoofings. **It is strongly discouraged to use the default value.**

## Testing

```
npm install
npm test
```

# Contact

For help on how to intergrate this package into your websites or apps, feel free to contact us at you -at- pelith -dot- com.
