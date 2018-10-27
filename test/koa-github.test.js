const app = require('./support/server');
const should = require('should');
const request = require('supertest');

describe('koa-gitlab', function() {
    describe('GET /gitlab/auth', function() {
        it('should redirect ok', function(done) {
            request(app)
                .get('/gitlab/auth')
                .expect(302, done);
        });
    });

    describe('GET /gitlab/auth/callback', function() {
        it('should 400', function(done) {
            request(app)
                .get('/gitlab/auth/callback?code=123')
                .expect(400, done);
        });

        it('should 403', function(done) {
            request(app)
                .get('/gitlab/auth/callback?code=123&state=123')
                .expect(403, done);
        });
    });
});
