import * as SAMLStrategy from "passport-saml";
import { fetch, toPassportConfig } from "passport-saml-metadata";
import * as https from "https";
import * as retry from "async-retry";

// tslint:disable-next-line: class-name
export class samlauthstrategyoptions {
    public callbackUrl:string = "auth/strategy/callback/";
    public entryPoint:string = "";
    public issuer:string = "";
    public audience:string = null;
    public cert:string = "";
    public signatureAlgorithm:string = "sha256";
    public callbackMethod:string = "POST";
    public verify:any;
}
// tslint:disable-next-line: class-name
export class samlauthstrategy {

    public name:string = "saml";
    public label:string = "Sign in with SAML";
    public icon:string = "fa-microsoft";
    public strategy:any = SAMLStrategy.Strategy;
    public options:samlauthstrategyoptions = new samlauthstrategyoptions();
}
interface IVerifyFunction { (error:any, profile:any): void; }
// tslint:disable-next-line: class-name
export class noderedcontribauthsaml {
    public type:string = "strategy";
    public authenticate:any = null;
    public users:any = null;
    public strategy:samlauthstrategy = new samlauthstrategy();
    private _users: any = {};
    private customverify:any;
    public static async configure(baseURL:string, saml_federation_metadata:string, issuer:string, customverify:any, saml_ca:string, identityProviderUrl:string, saml_cert:string):Promise<noderedcontribauthsaml> {
        var result:noderedcontribauthsaml = new noderedcontribauthsaml(baseURL);
        if(saml_federation_metadata !== null && saml_federation_metadata !== undefined) {
            var metadata:any = await noderedcontribauthsaml.parse_federation_metadata(saml_ca, saml_federation_metadata);
            result.strategy.options.entryPoint = metadata.identityProviderUrl;
            result.strategy.options.cert = metadata.cert;
            result.strategy.options.issuer = issuer;
        } else {
            result.strategy.options.entryPoint = identityProviderUrl;
            result.strategy.options.cert = saml_cert;
            result.strategy.options.issuer = issuer;
        }
        result.customverify = customverify;
        return result;
    }
    public static async parse_federation_metadata(tls_ca:String, url: string): Promise<any> {
        try {
            if (tls_ca !== "") {
                var rootCas = require('ssl-root-cas/latest').create();
                rootCas.push(tls_ca);
                // rootCas.addFile( tls_ca );
                https.globalAgent.options.ca = rootCas;
                require('https').globalAgent.options.ca = rootCas;
            }
        } catch (error) {
            console.log(error);
        }
        // if anything throws, we retry
        var metadata: any = await retry(async bail => {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
            var reader: any = await fetch({ url });
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
            if (reader === null || reader === undefined) { bail(new Error("Failed getting result")); return; }
            var config: any = toPassportConfig(reader);
            // we need this, for Office 365 :-/
            if (reader.signingCerts && reader.signingCerts.length > 1) {
                config.cert = reader.signingCerts;
            }
            return config;
        }, {
                retries: 50,
                onRetry: function (error: Error, count: number): void {
                    console.log("retry " + count + " error " + error.message + " getting " + url);
                }
            });
        return metadata;
    }
    constructor(baseURL:string) {
        this.strategy.options.callbackUrl = baseURL + "auth/strategy/callback/";
        // this.strategy.options.audience = baseURL;
        this.strategy.options.verify = (this.verify).bind(this);
        this.authenticate = (this._authenticate).bind(this);
        this.users = (this.fn_users).bind(this);
    }
    verify(profile:any, done:IVerifyFunction):void {
        var roles:string[] = profile["http://schemas.xmlsoap.org/claims/Group"];
        if(roles!==undefined) {
            if(roles.indexOf("nodered_users")!==-1 || roles.indexOf("nodered users")!==-1) { profile.permissions = "read"; }
            if(roles.indexOf("nodered_admins")!==-1 || roles.indexOf("nodered admins")!==-1) { profile.permissions = "*"; }
        }
        if(profile.permissions === undefined || profile.permissions === null) {
            return done("Permission denied",null);
        }
        profile.username = profile.nameID;
        if(this.customverify!==null && this.customverify!==undefined) {
            this.customverify(profile, (newprofile)=> {
                this._users[newprofile.nameID] = newprofile;
                done(null,newprofile);
            });
        } else {
            this._users[profile.nameID] = profile;
            done(null,profile);
        }
    }
    async _authenticate(profile:string | any, arg2:any):Promise<any> {
        var username:string = profile;
        if (profile.nameID) {
            username = profile.nameID;
        }
        return this.users(username);
    }
    async fn_users(username:string):Promise<any> {
        var user:any = this._users[username];
        // this._logger.silly("users: looking up " + username);
        return user;
    }
}
