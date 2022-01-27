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

For our example, we'll log in to Stripe.

First, we'll construct a new NetlifyGraphAuth instance. It requires the
name of the service and an appId.

```javascript
import NetlifyGraphAuth from 'netlify-graph-auth';

const APP_ID = YOUR_APP_ID;

const auth = new NetlifyGraphAuth({
  appId: APP_ID,
});
```

The NetlifyGraphAuth client has 3 methods, `isLoggedIn`, `login`, `logout`.

## Check if the user is loggedIn

The `isLoggedIn` method takes a service name as its only argument and
will return a promise with a boolean indicating if the user is logged
in to that service.

```javascript
auth.isLoggedIn('github').then(isLoggedIn => {
  if (isLoggedIn) {
    console.log('Already logged in to GitHub');
  } else {
    console.log('Not logged in to GitHub.');
  }
});
```

## Log the user in

The `login` method takes a service name as its only argument and will
take the client through the OAuth login flow for the service and
return a promise that resolves after the client finishes the flow.

After the client finishes, you can call `isLoggedIn` again to check if the
user successfully made it through the flow.

```javascript
auth
  .login('github')
  .then(() => {
    auth.isLoggedIn('github').then(isLoggedIn => {
      if (isLoggedIn) {
        console.log('Successfully logged in to GitHub');
      } else {
        console.log('Did not grant auth for GitHub');
      }
    });
  })
  .catch(e => console.error('Problem logging in', e));
```

## Log the user out

The `logout` method takes a service name as its only argument and will
log the client out and return a promise wrapping an object with a
`result` key whose value is either 'success' or 'failure' to indicate
whether the user is still logged in.

```javascript
auth.logout('github').then(response => {
  if (response.result === 'success') {
    console.log('Logout succeeded');
  } else {
    console.log('Logout failed');
  }
});
```