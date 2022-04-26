import { Base64 } from 'js-base64';
//import CBOR from 'cbor';

const refs = {};
const state = {};

let setState = (partialState) => {
    Object.keys(partialState).forEach(k => state[k] = partialState[k]);

    const old = document.body.querySelector("div");

    if (old) old.remove();

    const container = document.createElement('div');

    if (state.loading) {
        container.innerHTML += `<h2>Loading..</h2>`;
    } else {
        if (state.token) {
            if (state.verified) {
                container.innerHTML += `
                    <h4>Settings</h4>
                    <button id="addKey">Add Fido2 Key</button>
                    <button id="removeKey">Remove Fido2 Key</button>
                    <button id="logout">Logout</button>
                `;
            } else {
                container.innerHTML += `
                    <h4>Logged in</h4>
                    <button id="verify">Verify Email</button>
                    <button id="logout">Logout</button>
                `;
            }
        } else {
            container.innerHTML += `
                <h4>Please signup or login</h4>
                <button id="signup">Signup</button>
                <button id="login">Login</button>
            `;
        }
    }

    container.innerHTML += `
        <pre>State ${JSON.stringify({
            token_claim: state.token ? JSON.parse(Base64.decode(state.token.split('.')[1])) : null,
            ...state,
        }, null, 4)}</pre>
    `;

    document.body.appendChild(container);

    refs.signup = document.body.querySelector("#signup");
    refs.verify = document.body.querySelector("#verify");
    refs.login = document.body.querySelector("#login");
    refs.logout = document.body.querySelector("#logout");
    refs.addKey = document.body.querySelector("#addKey");
    refs.removeKey = document.body.querySelector("#removeKey");

    if (refs.signup) refs.signup.addEventListener("click", signup);
    if (refs.verify) refs.verify.addEventListener("click", verify);
    if (refs.login) refs.login.addEventListener("click", login);
    if (refs.logout) refs.logout.addEventListener("click", logout);
    if (refs.addKey) refs.addKey.addEventListener("click", addKey);
    if (refs.removeKey) refs.removeKey.addEventListener("click", removeKey);

    console.log("rendered");
};

setState({ token: null, verified: false, loading: false, keys: [] });

async function signup() {
    setState({ loading: true });

    let response = await fetch("http://localhost:8080/auth/signup", {
        method: "POST",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email: prompt("Mail"),
            password: prompt("Password")
        })
    });

    const { token } = await response.json();

    setState({ loading: false, token });

    console.log("logged in");
};

async function verify() {
    if (state.token == null) throw new Error("You need to be logged in");

    setState({ loading: true });

    let response = await fetch("http://localhost:8080/auth/verify", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${state.token}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ code: +prompt("Verification Code") })
    });

    if (response.status != 200) {
        setState({ verified: false, loading: false });
        return console.error("please try again");
    }

    console.log("verified");
    setState({ verified: true, loading: false });
}

async function login() {
    setState({ loading: true });

    let response = await fetch("http://localhost:8080/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: prompt("Mail"),
            password: prompt("Password")
        })
    });

    if (response.status > 299) {
        setState({ loading: false });
        return console.error("Please try again");
    }

    let body = await response.json();

    if (body.token) {
        setState({
            loading: false,
            token: body.token,
            verified: body.verified,
            keys: body.keys
        });

        return console.log("Logged in without fido!");
    }

    setState({ loading: false });

    console.log("Received challenge!");

    console.warn("Decode fields of challenge");

    let credentials = await navigator.credentials.get(body);

    console.warn("Encode fields of credentials");

    setState({ loading: true });

    response = await fetch("http://localhost:8080/auth/fido2/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credentials)
    });

    body = await response.json();

    if (response.status != 200) {
        setState({ loading: false });
        return console.error("Failed to login");
    }

    setState({
        loading: false,
        token: body.token,
        verified: body.verified,
        keys: body.keys
    });
    console.log("Logged in with fido!");

}

async function logout() {
    setState({
        token: null,
        verified: false,
        loading: false,
        keys: []
    });
    console.log("Logout")
}

async function addKey() {
    setState({ loading: true });

    let response = await fetch("http://localhost:8080/auth/fido2/challenges", {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}` },
    });

    let options = await response.json();
    options.publicKey.challenge = Base64.toUint8Array(options.publicKey.challenge);
    options.publicKey.user.id = Base64.toUint8Array(options.publicKey.user.id);

    if (options.publicKey.excludeCredentials) {
        options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
            type: cred.type,
            id: Base64.toUint8Array(cred.id)
        }));
    }

    setState({ loading: false });

    const credentials = await navigator.credentials.create(options);

    const mapped = { id: credentials.id, rawId: credentials.id, type: credentials.type, response: {} };
    mapped.response.attestationObject = Base64.fromUint8Array(new Uint8Array(
        credentials.response.attestationObject
    ), true);
    mapped.response.clientDataJSON = Base64.fromUint8Array(new Uint8Array(
        credentials.response.clientDataJSON
    ), true);

    console.log(credentials, mapped)

    setState({ loading: true });

    response = await fetch("http://localhost:8080/auth/fido2/keys", {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}`, "Content-Type": "application/json" },
        body: JSON.stringify(mapped)
    });

    let key = await response.json();

    if (response.status != 201) {
        setState({ loading: false });
        return console.error("please try again");
    }

    setState({ loading: false, keys: [...(state.keys ?? []), key.id] });
};

function arrayBufferToBase64(buffer) {
    let binary = '';
    let bytes = new Uint8Array( buffer );
    let len = bytes.byteLength;

    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }

    return window.btoa(binary);
}
