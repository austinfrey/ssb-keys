"use strict";
var sodium = require("chloride");

module.exports = {
  curves: ["ed25519"],

  generate: function (seed) {
    if (!seed) {
      seed = Buffer.alloc(32);
      sodium.randombytes(seed);
    }

    var keys = sodium.crypto_sign_seed_keypair(seed);

    return {
      curve: "ed25519",
      public: keys.publicKey,

      //so that this works with either sodium
      //or libsodium-wrappers (in browser)
      private: keys.privateKey || keys.secretKey,
    };
  },

  sign: function (privateKey, message) {
    return sodium.crypto_sign_detached(message, privateKey);
  },

  verify: function (publicKey, sig, message) {
    return sodium.crypto_sign_verify_detached(sig, message, publicKey);
  },
};
