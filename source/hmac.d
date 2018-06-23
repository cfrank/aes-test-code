// private ubyte[DIGEST_LEN] hmacHash(const(ubyte)[] data) {
//     ulong outputPtr;
//     ubyte[DIGEST_LEN] buffer = new ubyte[DIGEST_LEN];

//     EVP_add_digest(EVP_sha256());

//     this.mdContext = EVP_MD_CTX_new();

//     if (this.mdContext == null) {
//         throw new SimpleAESException("Failed to create OpenSSL MD context");
//     }

//     const(EVP_MD)* md = EVP_sha256();

//     if (EVP_DigestInit_ex(this.mdContext, md, null) != 1) {
//         throw new SimpleAESException("Failed to create message digest");
//     }

//     EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, null,
//             this.key.ptr, cast(int) key.length);

//     if (pkey == null) {
//         throw new SimpleAESException("Failed to generate pkey");
//     }

//     if (EVP_DigestSignInit(this.mdContext, null, md, null, pkey) != 1) {
//         throw new SimpleAESException("Failed to initialize the digest");
//     }

//     if (EVP_DigestSignUpdate(this.mdContext, data.ptr, data.length) != 1) {
//         throw new SimpleAESException("Failed while updating the digest");
//     }

//     if (EVP_DigestSignFinal(this.mdContext, buffer.ptr, &outputPtr) != 1) {
//         throw new SimpleAESException("Failed while finalizing the digest");
//     }

//     return buffer;
// }