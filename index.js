const base64url = sjcl.codec.base64url;
const sha256 = sjcl.hash.sha256;
const random = sjcl.random;

class OAuthCredentials {
    constructor(options) {
        this.access_token = options["access_token"];
        this.refresh_token = options["refresh_token"];
        this.token_type = options["token_type"];
        this.expires_in = options["expires_in"];
    }
}

class UserEntity {
    constructor(options) {
        this.displayName = options["displayName"];
        this.userPrincipalName = options["userPrincipalName"];
        this.givenName = options["givenName"];
        this.surname = options["surname"];
        this.id = options["id"];
    }
}

class OrgEntity {
    constructor(options) {
        this.id = options["id"]
        this.displayName = options["displayName"];
    }
}

const BASE = "https://graph.microsoft.com/v1.0";
class MSGraphClient {
    constructor(options) {
        this.credentials = options["credentials"];
    }

    async _call(path) {
        let response = await fetch(BASE + path, {
            headers: {
                "Authorization": `Bearer ${this.credentials.access_token}`,
            }
        });
        let data = await response.json();
        return data;
    }

    async me() {
        return new UserEntity(await this._call('/me'));
    }

    async organization() {
        try {
            return (await this._call('/organization'))["value"].map(x => new OrgEntity(x));
        } catch (e) {
            return null;
        }
    }
}

async function redeemToken(client_id, code, redirect_uri, code_verifier) {
    console.log("Redeeming token...");

    let request_data = new URLSearchParams({
        client_id: client_id,
        scope: "User.Read",
        code: code,
        redirect_uri: redirect_uri,
        grant_type: "authorization_code",
        code_verifier: code_verifier,
    });

    let response = await fetch(`https://login.microsoftonline.com/common/oauth2/v2.0/token`, {
        method: "POST",
        body: request_data,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    });
    let response_data = await response.json();

    history.replaceState({}, "MS IDP Demo", redirect_uri);
    return new OAuthCredentials(response_data);
}

function makeAuthUrl(client_id, tenant_id) {
    // Generate code verifier
    let code_verifier = base64url.fromBits(random.randomWords(10));
    let code_challenge = base64url.fromBits(sha256.hash(code_verifier));

    let current_uri = new URL(location.href);
    current_uri.search = "";
    let redirect_uri = current_uri.toString();
    console.log("redirect_uri=", redirect_uri);

    let state = base64url.fromBits(random.randomWords(10));
    sessionStorage.setItem(`oauth-login-${state}-verifier`, code_verifier);
    sessionStorage.setItem(`oauth-login-${state}-uri`, redirect_uri);

    let url = new URL(`https://login.microsoftonline.com/${tenant_id}/oauth2/v2.0/authorize`);
    let params = new URLSearchParams({
        client_id: client_id,
        response_type: "code",
        redirect_uri: redirect_uri,
        response_mode: "query",
        state: state,
        scope: "User.Read",
        code_challenge: code_challenge,
        code_challenge_method: "S256",
        prompt: "select_account"
    });
    url.search = params.toString();
    return url;
}

async function onCallback(client_id) {
    let code = url.searchParams.get("code");
    let state = url.searchParams.get("state");
    let code_verifier = sessionStorage.getItem(`oauth-login-${state}-verifier`);
    let redirect_uri = sessionStorage.getItem(`oauth-login-${state}-uri`);

    let credentials = await redeemToken(client_id, code, redirect_uri, code_verifier);
    let graphClient = new MSGraphClient({
        credentials
    });

    return graphClient;
}
