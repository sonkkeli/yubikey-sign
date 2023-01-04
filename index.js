var graphene = require("graphene-pk11");
var Module = graphene.Module;

// Using Node v18

// To make the script work, run (or where ever your confs are located):
// export SOFTHSM2_CONF=$HOME/soft/softhsm2.conf

// How to configure the underlying SoftHSM2
// ./configure --with-openssl=/usr/lib/ssl --enable-eddsa=yes
// More: https://github.com/opendnssec/SoftHSMv2

var lib = "/usr/local/lib/softhsm/libsofthsm2.so";

const CKK_EC_EDWARDS = 0x40; //$HOME/SoftHSMv2/src/lib/pkcs11/pkcs11.h
const CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055;
const CKM_EDDSA = 0x1057;

// $HOME/SoftHSMv2/src/lib/crypto/OSSLUtil.cpp L#190
const NAMED_CURVE_FOR_EDWARDS_25519 = Buffer.from(
  "130C656477617264733235353139",
  "hex"
);

function signAndVerify(session, dataToSign, keys) {
  var sign = session.createSign(CKM_EDDSA, keys.privateKey);
  var signature = sign.once(dataToSign); // This will be placed on the integrity block.

  console.log("Signature:", signature.toString("hex"));

  var verify = session.createVerify(CKM_EDDSA, keys.publicKey);
  var verify_result = verify.once(dataToSign, signature);

  console.log("isVerified= ", verify_result);

  return signature;
}

function readKeyWithIdAndType(session, keyClass, keyId) {
  const matches = session.find({ class: keyClass, id: keyId });
  return session.getObject(matches.innerItems[0]);
}

function readKeyPairWithId(session, keyId) {
  return {
    publicKey: readKeyWithIdAndType(
      session,
      graphene.ObjectClass.PUBLIC_KEY,
      keyId
    ),
    privateKey: readKeyWithIdAndType(
      session,
      graphene.ObjectClass.PRIVATE_KEY,
      keyId
    ),
  };
}

function generateKeysWithId(session, keyId) {
  return session.generateKeyPair(
    CKM_EC_EDWARDS_KEY_PAIR_GEN,
    {
      keyType: CKK_EC_EDWARDS,
      token: true,
      private: false,
      encrypt: false,
      verify: true,
      derive: false,
      paramsEC: NAMED_CURVE_FOR_EDWARDS_25519, // should this be ECDSA instead?
      modifiable: false,
      label: "Generated EC Edwards pubK",
      wrap: true,
      id: keyId,
    },
    {
      keyType: CKK_EC_EDWARDS,
      token: true,
      private: false,
      sensitive: true,
      decrypt: false,
      sign: true,
      derive: false,
      modifiable: false,
      extractable: false,
      label: "Generated EC Edwards privK",
      id: keyId,
    }
  );
}

function printKeyDetails(keys) {
  // These don't work
  // console.log(JSON.stringify(keys.publicKey));
  // console.log(keys.publicKey.get("key"));
  // console.log(keys.publicKey.get("ski"));
  // console.log(keys.publicKey.get("value"));
  // console.log(keys.publicKey.getAttribute({
  //   value: null
  // }))
}

var mod = Module.load(lib, "SoftHSM");
mod.initialize();

var slot = mod.getSlots(0);

graphene.Mechanism.vendor(
  "CKM_EC_EDWARDS_KEY_PAIR_GEN",
  CKM_EC_EDWARDS_KEY_PAIR_GEN
);
graphene.Mechanism.vendor("CKM_EDDSA", CKM_EDDSA);

if (slot.flags & graphene.SlotFlag.TOKEN_PRESENT) {
  var session = slot.open(
    graphene.SessionFlag.RW_SESSION | graphene.SessionFlag.SERIAL_SESSION
  );
  session.login("1234", graphene.UserType.USER);

  // Only when run the first time / want to generate a new key.
  // const keys = generateKeysWithId(session, Buffer.from([1, 2, 3, 4, 5]));

  const keys = readKeyPairWithId(session, Buffer.from([1, 2, 3, 4, 5]));

  const dataToSign = "helloworld"; // Here the hash of the web bundle.
  /*const signature =*/ signAndVerify(session, dataToSign, keys);

  printKeyDetails(keys);

  session.logout();
  session.close();
} else {
  console.error("Slot is not initialized");
}

mod.finalize();
