koa-gitlab [![Build Status](https://secure.travis-ci.org/koajs/koa-gitlab.png)](http://travis-ci.org/koajs/koa-gitlab)
==========

simple gitlab auth middleware for koa

[![NPM](https://nodei.co/npm/koa-gitlab.png?downloads=true)](https://nodei.co/npm/koa-gitlab/)

## Example

```js
const Koa = require('koa');
const session = require('koa-session');
const gitlabAuth = require('./');

const app = new Koa();

app.name = 'nae-web';
app.keys = ['key1', 'key2'];

app.use(session(app));

app.use(
    gitlabAuth({
        clientID:
            'c5cab72c81c43289f918367e651af278bbf967c8a5de2b406c0ce8831eacfeaa',
        clientSecret:
            'b4c56b6aed0d2eef0ffcf34ae5c975729e718be0a0041a83daa5564974e46a06',
        callbackURL: 'http://localhost:7001/gitlab/auth/callback',
        userKey: 'user',
        timeout: 10000
    })
);

app.use(async ctx => {
    if (!ctx.session.gitlabToken) {
        ctx.body =
            '<a href="/gitlab/auth?redirect_uri=/callback">login with gitlab</a>';
    } else {
        ctx.body = `<pre>${JSON.stringify(ctx.session.user, null, 4)}</pre>`;
    }
});

app.on('error', err => {
    if (!err.status || err.status >= 500) {
        console.error(err);
    }
});

app.listen(7001);
```

## Options

```
  @param {Object} options
    - [String] gitlabHost     host, default is https://gitlab.com
    - [String] clientID      gitlab client ID     // regist in https://gitlab.com/profile/applications
    - [String] clientSecret  gitlab client secret
    - [String] callbackURL   gitlab redirect url
    - [String] signinPath    sign in with gitlab's triggle path, default is `/gitlab/auth`
    - [String] tokenKey      session key, default is gitlabToken
    - [String] userKey       user key, if set user key, will request gitlab once to get the user info
    - [Array]  scope         A comma separated list of scopes
    - [Number] timeout       request gitlab api timeout
    - [String] redirect      redirect key when call signinPath, so we can redirect after auth, default is `redirect_uri`
```

* clientID, clentSecret and callbackURL are registered in https://gitlab.com/profile/applications .
* if you set userKey field, `koa-gitlab` will request to get the user info and set this object to `this.session[options.userKey]`, otherwise `koa-gitlab` will not do this request.
* if you triggle by `/gitlab/auth?redirect_uri=/callback`, `koa-gitlab` will redirect to `/callback` after auth, and the redirect_uri only accept start with `/`.

## Thanks

* [koa-github](https://github.com/koajs/koa-github)

## Licences
(The MIT License)

Copyright (c) 2013 aui and other contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
