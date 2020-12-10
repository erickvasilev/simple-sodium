const _sodium = require('libsodium-wrappers');

(function() {

async function oneway (plain_text, length) {
         await _sodium.ready;
         const sodium = _sodium;
         let user_password_length = length;
         let user_password = _sodium.crypto_generichash(user_password_length, sodium.from_string(plain_text));
         let user_password_hex = sodium.to_hex(user_password);
         return user_password_hex
         
         
    }  

async function encrypt (key, plain_text) {
         await _sodium.ready;
         const sodium = _sodium;
         
         let user_salt_length = 16;
         let user_salt = sodium.crypto_generichash(user_salt_length, sodium.from_string(key));
         let user_salt_hex = sodium.to_hex(user_salt);
         
         let user_hash_length = 12;
         let user_hash = sodium.crypto_generichash(user_hash_length, sodium.from_string(key));
         let user_hash_hex = sodium.to_hex(user_hash);
         
         let encoder = new TextEncoder();
         let user_salt_key = encoder.encode(user_salt_hex);
         let user_hash_key = encoder.encode(user_hash_hex);
         
         let encryption = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain_text, null, null, user_hash_key, user_salt_key)
         let encrypted = sodium.to_hex(encryption);
         return encrypted
         
         
    }
    
async function decrypt (key, chipertext) {
         await _sodium.ready;
         const sodium = _sodium;
         
         let user_salt_length = 16;
         let user_salt = sodium.crypto_generichash(user_salt_length, sodium.from_string(key));
         let user_salt_hex = sodium.to_hex(user_salt);
         
         let user_hash_length = 12;
         let user_hash = sodium.crypto_generichash(user_hash_length, sodium.from_string(key));
         let user_hash_hex = sodium.to_hex(user_hash);
         
         let encoder = new TextEncoder();
         let user_salt_key = encoder.encode(user_salt_hex);
         let user_hash_key = encoder.encode(user_hash_hex);
         
        let hex_to_uint8array = sodium.from_hex(chipertext)
        let decryption = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                null,
                hex_to_uint8array,
                null,
                user_hash_key,
                user_salt_key
            )
            
        let decrypted = sodium.to_string(decryption);
        return decrypted
         
         
    }    

module.exports.encrypt = async function(key, plain_text) {
        return encrypt(key, plain_text);
}

module.exports.decrypt = async function(key, chipertext) {
        return decrypt(key, chipertext);
}

module.exports.oneway = async function(plain_text, length) {
        return oneway(plain_text, length);
}
    
}());    




