// Load modules

var Code = require('code');
var Hapi = require('./helpers/hapi');
var Hoek = require('hoek');
var Inert = require('..');
var Lab = require('lab');
var Path = require('path');


// Declare internals

var internals = {};


// Test shortcuts

var lab = exports.lab = Lab.script();
var describe = lab.describe;
var it = lab.it;
var expect = Code.expect;


describe('security', function () {

    var provisionServer = function () {

        var server = new Hapi.Server();
        server.connection({ routes: { files: { relativeTo: __dirname } } });
        server.register(Inert, Hoek.ignore);
        return server;
    };

    it('blocks path traversal to files outside of hosted directory is not allowed with null byte injection', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/%00/../security.js', function (res) {

            expect(res.statusCode).to.equal(404);
            done();
        });
    });

    it('blocks path traversal to files outside of hosted directory is not allowed', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/../security.js', function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('blocks path traversal to files outside of hosted directory is not allowed with encoded slash', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/..%2Fsecurity.js', function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('blocks path traversal to files outside of hosted directory is not allowed with double encoded slash', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/..%252Fsecurity.js', function (res) {

            expect(res.statusCode).to.equal(404);
            done();
        });
    });

    it('blocks path traversal to files outside of hosted directory is not allowed with unicode encoded slash', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/..\u2216security.js', function (res) {

            expect(res.statusCode).to.equal(404);
            done();
        });
    });

    it('blocks null byte injection when serving a file', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/{path*}', handler: { directory: { path: './directory' } } });

        server.inject('/index%00.html', function (res) {

            expect(res.statusCode).to.equal(404);
            done();
        });
    });

    it('blocks access to files outside of base directory for file handler', function (done) {

        var server = provisionServer();

        var secureHandler = { file: { confine: './directory', path: Path.join(__dirname, 'security.js') } };
        server.route({ method: 'GET', path: '/secure', handler: secureHandler });
        server.route({ method: 'GET', path: '/open', handler: Hoek.applyToDefaults(secureHandler, { file: { confine: false } }) });

        server.inject('/secure', function (res1) {

            expect(res1.statusCode).to.equal(403);
            server.inject('/open', function (res2) {

                expect(res2.statusCode).to.equal(200);
                done();
            });
        });
    });

    it('blocks path traversal to files outside of base directory for file handler', function (done) {

        var server = provisionServer();
        server.route({ method: 'GET', path: '/file', handler: { file: { confine: './directory', path: '../security.js' } } });

        server.inject('/file', function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('blocks access to files outside of base directory for reply.file()', function (done) {

        var server = provisionServer();
        var fileHandler = function (request, reply) {

            reply.file(Path.join(__dirname, 'security.js'), { confine: Path.join(__dirname, 'directory') });
        };

        server.route({ method: 'GET', path: '/file', handler: fileHandler });

        server.inject('/file', function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });

    it('blocks path traversal to files outside of base directory for reply.file()', function (done) {

        var server = provisionServer();
        var fileHandler = function (request, reply) {

            reply.file('../security.js', { confine: Path.join(__dirname, 'directory') });
        };

        server.route({ method: 'GET', path: '/file', handler: fileHandler });

        server.inject('/file', function (res) {

            expect(res.statusCode).to.equal(403);
            done();
        });
    });
});
