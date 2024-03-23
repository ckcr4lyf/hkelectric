import * as jose from 'jose';

// See devlog for how we got this
const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJdIFoYu18LMBqJkaRL2
jJv/bUbfcbS6UFYwnsa8F6tKi7/Ai71OUlNZJLZPtjApXjbvd98Af4XEPjADqyDS
LROoNyNTwqbVE8vcsSYbX5np+AyjhmlXSTDp10Kaf4uiVYr6DP/Q/CC4xtUc3vbs
hQCVTxbxX2e1PEQAb7jXyFKbpjNK5GI25mYxyUQE/PI6O2KZusn3+ToZbyQsRoeE
57PrQUdBVgEC/V6gLqjqK0jRX81TEfXgwT+AF/+cPbokmEa+C3V09EU43a9Z7XP4
CloQKtXdQH/GtXwVjsmeXqBa2Zb3qVBy8WXDzofOImMi2e38NJafE4Oends3ijNR
1QIDAQAB
-----END PUBLIC KEY-----`

const rsaPublicKey = await jose.importSPKI(publicKey, 'rsa');

export class HKElectricApi {

    private cookie: string;

    constructor(private username?: string, private password?: string) {
        // TODO: error handling when undefined
    }

    async login() {
        const plaintextLoginReq = {
            UserName: this.username,
            Password: this.password,
            isViewBill: false,
            accountToView: "",
        };

        const jwe = await new jose.CompactEncrypt(Buffer.from(JSON.stringify(plaintextLoginReq))).setProtectedHeader({
            alg: 'RSA-OAEP-256',
            enc: 'A256GCM'
        }).encrypt(rsaPublicKey);

        const rsp = await fetch('https://aol.hkelectric.com/AOL/api/login/Login', {
            method: 'POST',
            body: JSON.stringify({
                EncryptedData: jwe,
            }),
        });

        // YOLO
        const response: any = await rsp.json();

        if (response.StateInfo.Result !== 'SUCCESS'){
            // TODO: Better handling here.
            console.log(`something fucked up`);
            process.exit(1);
        }

        // Hacky cookie manipulation but it works
        this.cookie = rsp.headers.getSetCookie().map(cookie => cookie.split(';')[0]).join('; ');
    }
}