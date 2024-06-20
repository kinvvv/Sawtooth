const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const {Secp256k1PrivateKey} = require('sawtooth-sdk-js/signing/secp256k1')
const {CryptoFactory, createContext} = require('sawtooth-sdk-js/signing')

//This create a new private key and return hex version of the key
const createPrivateKey = () => {
    const msg = randomBytes(32)
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))
    const pubKey = secp256k1.publicKeyCreate(privKey)
    const sigObj = secp256k1.ecdsaSign(msg, privKey)
    console.log(secp256k1.ecdsaVerify(sigObj.signature, msg, pubKey))
    return privKey.toString('hex')
}

const privateKeyHexStr = createPrivateKey();

//Create Instance of the private key with a internal class
const privateKey = new Secp256k1PrivateKey(privateKeyHexStr);

const context = createContext('secp256k1');

//Create a new signer to sign the payload
const signer = new CryptoFactory(context).newSigner(privateKey)