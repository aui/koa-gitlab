const debug = require('debug')('koa-gitlab');
const utility = require('utility');
const Request = require('request');
const util = require('util');
const urlParse = require('url').parse;
const assert = require('assert');

const defaultOptions = {
    gitlabHost: 'https://gitlab.com',
    tokenKey: 'gitlabToken',
    signinPath: '/gitlab/auth',
    timeout: 5000,
    scope: [],
    redirect: 'redirect_uri'
};

const request = options =>
    new Promise((resolve, reject) => {
        Request(options, (error, response) => {
            if (error) {
                reject(error);
            } else {
                resolve(response);
            }
        });
    });

/**
 * auth with gitlab
 * need use session middleware before
 * see http://developer.gitlab.com/v3/oauth/#web-application-flow
 *
 * @param {Object} options
 *   - [String] gitlabHost     host, default is https://.com
 *   - [String] clientID      gitlab client ID
 *   - [String] clientSecret  gitlab client secret
 *   - [String] callbackURL   gitlab callback url
 *   - [String] signinPath    sign in with gitlab's triggle path, default is /gitlab/auth
 *   - [String] tokenKey      session key, default is gitlabToken
 *   - [String] userKey       user key, if set user key, will request gitlab once to get the user info
 *   - [Array]  scope         A comma separated list of scopes
 *   - [Number] timeout       request gitlab api timeout
 *   - [String] redirect      redirect key when call signinPath, so we can redirect after auth, default is redirect_uri
 *
 */
module.exports = options => {
    options = options || {};
    if (!options.clientID || !options.clientSecret || !options.callbackURL) {
        throw new Error(
            'gitlab auth need clientID, clientSecret and callbackURL'
        );
    }
    options = Object.assign({}, defaultOptions, options);
    options.callbackPath = urlParse(options.callbackURL).path;

    debug('init gitlab auth middleware with options %j', options);

    return async (ctx, next) => {
        if (!ctx.session) {
            return ctx.throw('gitlab auth need session', 500);
        }

        // first step: redirect to gitlab
        if (ctx.path === options.signinPath) {
            const state = utility.randomString();
            let redirectUrl = util.format(
                '%sclient_id=%s&redirect_uri=%s&scope=%s&state=%s&response_type=code',
                `${options.gitlabHost}/oauth/authorize?`,
                options.clientID,
                options.callbackURL,
                options.scope,
                state
            );

            ctx.session.gitlabstate = state;

            //try to get the redirect url and set it to session
            try {
                const redirect = decodeURIComponent(
                    urlParse(ctx.url, true).query[options.redirect] || ''
                );
                if (redirect[0] === '/') {
                    ctx.session.gitlabredirect = redirect;
                    debug('get gitlab callback redirect uri: %s', redirect);
                }
            } catch (err) {
                debug('decode redirect uri error');
            }
            debug('request gitlab auth, redirect to %s', redirectUrl);
            //if already signin
            if (ctx.session[options.tokenKey]) {
                debug('already has gitlab token');
                redirectUrl = ctx.session.gitlabredirect || '/';
                delete ctx.session.gitlabredirect;
            }

            return ctx.redirect(redirectUrl);
        }

        // secound step: gitlab callback
        if (ctx.path === options.callbackPath) {
            //if already signin
            if (ctx.session[options.tokenKey]) {
                debug('already has gitlab token');
                return ctx.redirect('/');
            }

            debug('after auth, jump from gitlab.');
            const url = urlParse(ctx.request.url, true);

            // must have code
            if (!url.query.code || !url.query.state) {
                debug('request url need `code` and `state`');
                return ctx.throw(400);
            }

            // check the state, protect against cross-site request forgery attacks
            if (url.query.state !== ctx.session.gitlabstate) {
                debug(
                    'request state is %s, but the state in session is %s',
                    url.query.state,
                    ctx.session.gitlabstate
                );
                delete ctx.session.gitlabstate;
                return ctx.throw(403);
            }

            //step three: request to get the access token
            const tokenUrl = `${options.gitlabHost}/oauth/token`;
            const requsetBody = {
                client_id: options.clientID,
                client_secret: options.clientSecret,
                code: url.query.code,
                grant_type: 'authorization_code',
                //  api: The redirect_uri must match the redirect_uri used in the original authorization request.
                redirect_uri: options.callbackURL
            };
            debug('request the access token with data: %j', requsetBody);
            let token;
            try {
                const result = await request({
                    url: tokenUrl,
                    method: 'POST',
                    json: true,
                    timeout: options.timeout,
                    body: requsetBody
                });
                assert.equal(
                    result.statusCode,
                    200,
                    'response status ' + result.statusCode + ' not match 200'
                );

                token = result.body.access_token;
                assert(token, 'response without access_token');
            } catch (err) {
                return ctx.throw(
                    'request gitlab token error: ' + err.message,
                    500
                );
            }

            ctx.session[options.tokenKey] = token;
            debug(
                'get access_token %s and store in session.%s',
                token,
                options.tokenKey
            );
            delete ctx.session.gitlabstate;

            //step four: if set userKey, get user
            if (options.userKey) {
                let result;
                try {
                    result = await request({
                        method: 'GET',
                        url: `${options.gitlabHost}/api/v4/user`,
                        json: true,
                        timeout: options.timeout,
                        headers: {
                            Authorization: `Bearer ${token}`
                        }
                    });
                    assert.equal(
                        result.statusCode,
                        200,
                        'response status ' +
                            result.statusCode +
                            ' not match 200'
                    );
                    assert(result.body, 'response without user info');
                } catch (err) {
                    return ctx.throw(
                        'request github user info error: ' + err.message,
                        500
                    );
                }
                debug(
                    'get user info %j and store in session.%s',
                    result.body,
                    options.userKey
                );
                ctx.session[options.userKey] = result.body;
            }

            const gitlabredirect = ctx.session.gitlabredirect || '/';
            delete ctx.session.gitlabredirect;
            return ctx.redirect(gitlabredirect);
        }

        await next();
    };
};
