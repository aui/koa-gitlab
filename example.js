//use http://localhost:7001 to test

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
console.log('open http://localhost:7001/ in your browser!');
