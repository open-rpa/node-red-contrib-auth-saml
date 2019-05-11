"# node-red-contrib-auth-saml" 

Install using npm
```
npm i node-red-contrib-auth-saml
```

declare module using either
```javascript
var samlauth = require("node-red-contrib-auth-saml");
```
or using typescript
```typescript
import * as samlauth from "node-red-contrib-auth-saml";
```
then initilize if you have an URL for FederationMetadata
```typescript
settings.adminAuth = await samlauth.noderedcontribauthsaml.configure("http://localhost:1880/", "https://login.microsoftonline.com/common/FederationMetadata/2007-06/FederationMetadata.xml", "myissuereid", 
(profile:string | any, done:any)=> {
    profile.permissions = "read";
    profile.permissions = "*";
    done(profile);
});
```
else, supply at identityProviderUrl and saml_cert ( if you need to add a chain to trusted ca's, also supply saml_ca)
```typescript
settings.adminAuth = await samlauth.noderedcontribauthsaml.configure("http://localhost:1880/", "", "myissuereid", 
(profile:string | any, done:any)=> {
    profile.permissions = "read";
    profile.permissions = "*";
    done(profile);
}, fs.readFileSync("ca.crt", "utf8"), "https://sso.mydomain.com/adfs/ls/", fs.readFileSync("signing.crt", "utf8"));
```
