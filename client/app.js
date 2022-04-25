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
                    <h4>Add fido2 key</h4>
                    <button id="addKey">Add Key</button>
                `;
            } else {
                container.innerHTML += `
                    <h4>Logged in</h4>
                    <button id="verify">Verify Email</button>
                `;
            }
        } else {
            container.innerHTML += `
                <h4>Please signup or login</h4>
                <button id="signup">Signup</button>
            `;
        }
    }

    container.innerHTML += `<pre>${JSON.stringify(state, null, 4)}</pre>`;

    document.body.appendChild(container);

    refs.signup = document.body.querySelector("#signup");
    refs.verify = document.body.querySelector("#verify");
    refs.addKey = document.body.querySelector("#addKey");

    if (refs.signup) refs.signup.addEventListener("click", signup);
    if (refs.verify) refs.verify.addEventListener("click", verify);
    if (refs.addKey) refs.addKey.addEventListener("click", addKey);

    console.log("rendered");
};

setState({ token: null, verified: false, loading: false, fido: false });

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

async function addKey() {
    setState({ loading: true });

    let response = await fetch("http://localhost:8080/auth/fido2/challenges", {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}` },
    });

    const toByteArr = str => Uint8Array.from(str, c => c.charCodeAt(0));

    let options = await response.json();
    options.publicKey.challenge = toByteArr(options.publicKey.challenge);
    options.publicKey.user.id = toByteArr(options.publicKey.user.id);

    setState({ loading: false });

    const credentials = await navigator.credentials.create(options);

    const mapped = { id: credentials.id, rawId: credentials.id, type: credentials.type, response: {} };
    mapped.response.attestationObject = arrayBufferToBase64(
        credentials.response.attestationObject
    );
    mapped.response.clientDataJSON = arrayBufferToBase64(
        credentials.response.clientDataJSON
    );

    console.log(credentials, mapped)

    setState({ loading: true });

    response = await fetch("http://localhost:8080/auth/fido2/keys", {
        method: "POST",
        headers: { "Authorization": `Bearer ${state.token}`, "Content-Type": "application/json" },
        body: JSON.stringify(mapped)
    });

    if (response.status != 200) {
        setState({ loading: false });
        return console.error("please try again");
    }

    setState({ loading: false, fido: true });

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
