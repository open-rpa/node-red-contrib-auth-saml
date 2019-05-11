"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const SAMLStrategy = require("passport-saml");
const passport_saml_metadata_1 = require("passport-saml-metadata");
const https = require("https");
const retry = require("async-retry");
// tslint:disable-next-line: class-name
class samlauthstrategyoptions {
    constructor() {
        this.callbackUrl = "auth/strategy/callback/";
        this.entryPoint = "";
        this.issuer = "";
        this.audience = null;
        this.cert = "";
        this.signatureAlgorithm = "sha256";
        this.callbackMethod = "POST";
    }
}
exports.samlauthstrategyoptions = samlauthstrategyoptions;
// tslint:disable-next-line: class-name
class samlauthstrategy {
    constructor() {
        this.name = "saml";
        this.label = "Sign in with SAML";
        this.icon = "fa-microsoft";
        this.strategy = SAMLStrategy.Strategy;
        this.options = new samlauthstrategyoptions();
    }
}
exports.samlauthstrategy = samlauthstrategy;
// tslint:disable-next-line: class-name
class noderedcontribauthsaml {
    constructor(baseURL) {
        this.type = "strategy";
        this.authenticate = null;
        this.users = null;
        this.strategy = new samlauthstrategy();
        this._users = {};
        this.strategy.options.callbackUrl = baseURL + "auth/strategy/callback/";
        // this.strategy.options.audience = baseURL;
        this.strategy.options.verify = (this.verify).bind(this);
        this.authenticate = (this._authenticate).bind(this);
        this.users = (this.fn_users).bind(this);
    }
    static async configure(baseURL, saml_federation_metadata, issuer, customverify, saml_ca, identityProviderUrl, saml_cert) {
        var result = new noderedcontribauthsaml(baseURL);
        if (saml_federation_metadata !== null && saml_federation_metadata !== undefined) {
            var metadata = await noderedcontribauthsaml.parse_federation_metadata(saml_ca, saml_federation_metadata);
            result.strategy.options.entryPoint = metadata.identityProviderUrl;
            result.strategy.options.cert = metadata.cert;
            result.strategy.options.issuer = issuer;
        }
        else {
            result.strategy.options.entryPoint = identityProviderUrl;
            result.strategy.options.cert = saml_cert;
            result.strategy.options.issuer = issuer;
        }
        result.customverify = customverify;
        return result;
    }
    static async parse_federation_metadata(tls_ca, url) {
        try {
            if (tls_ca !== "") {
                var rootCas = require('ssl-root-cas/latest').create();
                rootCas.push(tls_ca);
                // rootCas.addFile( tls_ca );
                https.globalAgent.options.ca = rootCas;
                require('https').globalAgent.options.ca = rootCas;
            }
        }
        catch (error) {
            console.log(error);
        }
        // if anything throws, we retry
        var metadata = await retry(async (bail) => {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
            var reader = await passport_saml_metadata_1.fetch({ url });
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
            if (reader === null || reader === undefined) {
                bail(new Error("Failed getting result"));
                return;
            }
            var config = passport_saml_metadata_1.toPassportConfig(reader);
            // we need this, for Office 365 :-/
            if (reader.signingCerts && reader.signingCerts.length > 1) {
                config.cert = reader.signingCerts;
            }
            return config;
        }, {
            retries: 50,
            onRetry: function (error, count) {
                console.log("retry " + count + " error " + error.message + " getting " + url);
            }
        });
        return metadata;
    }
    verify(profile, done) {
        var roles = profile["http://schemas.xmlsoap.org/claims/Group"];
        if (roles !== undefined) {
            if (roles.indexOf("nodered_users") !== -1 || roles.indexOf("nodered users") !== -1) {
                profile.permissions = "read";
            }
            if (roles.indexOf("nodered_admins") !== -1 || roles.indexOf("nodered admins") !== -1) {
                profile.permissions = "*";
            }
        }
        profile.username = profile.nameID;
        if (this.customverify !== null && this.customverify !== undefined) {
            this.customverify(profile, (newprofile) => {
                this._users[newprofile.nameID] = newprofile;
                if (profile.permissions === undefined || profile.permissions === null) {
                    return done("Permission denied", null);
                }
                done(null, newprofile);
            });
        }
        else {
            this._users[profile.nameID] = profile;
            if (profile.permissions === undefined || profile.permissions === null) {
                return done("Permission denied", null);
            }
            done(null, profile);
        }
    }
    async _authenticate(profile, arg2) {
        var username = profile;
        if (profile.nameID) {
            username = profile.nameID;
        }
        return this.users(username);
    }
    async fn_users(username) {
        var user = this._users[username];
        // this._logger.silly("users: looking up " + username);
        return user;
    }
}
exports.noderedcontribauthsaml = noderedcontribauthsaml;
//# sourceMappingURL=node-red-contrib-auth-saml.js.map