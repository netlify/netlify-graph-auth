# Netlify Graph Authentication Helpers for browsers
Before you can make queries on behalf of your users against 3rd-party services like Stripe,
the client needs to grant access to your app through an OAuth flow.

Netlify Graph provides an easy-to-use javascript auth library to manage
authenticating your clients with 3rd-party services.

## Install
Add the netlify-graph-auth library to your app:

```
npm install netlify-graph-auth
```

## Create an Auth Client

For our example, we'll log in to GitHub.

First, we'll construct a new NetlifyGraphAuth instance with our siteId.

```javascript
import NetlifyGraphAuth from 'netlify-graph-auth';
import process from 'process';

const auth = new NetlifyGraphAuth({
  siteId: process.env.SITE_ID,
});
```

The NetlifyGraphAuth client has 3 methods, `isLoggedIn`, `login`, `logout`.

## Check if the user is loggedIn

The `isLoggedIn` method takes a service name as its only argument and
will return a promise with a boolean indicating if the user is logged
in to that service.

```javascript
const isLoggedIn = await auth.isLoggedIn('github');
if (isLoggedIn) {
  console.log('Already logged in to GitHub');
} else {
  console.log('Not logged in to GitHub.');
}
```

## Log the user in

The `login` method takes a service name as its only argument and will
take the client through the OAuth login flow for the service and
return a promise that resolves after the client finishes the flow.

After the client finishes, you can call `isLoggedIn` again to check if the
user successfully made it through the flow.

```javascript
try {
  // Prompt the user to log into GitHub
  await auth.login('github');

  // Check to see if they logged in successfully
  const isLoggedIn = await auth.isLoggedIn('github');

  if (isLoggedIn) {
    console.log('Successfully logged in to GitHub');
  } else {
    console.log('Did not grant auth for GitHub');
  }
} catch (error) {
  console.error('Problem logging in', error);
}
```

## Log the user out

The `logout` method takes a service name as its only argument and will
log the client out and return a promise wrapping an object with a
`result` key whose value is either 'success' or 'failure' to indicate
whether the user is still logged in.

```javascript
const response = await auth.logout('github');

if (response.result === 'success') {
  console.log('Logout succeeded');
} else {
  console.log('Logout failed');
}
```