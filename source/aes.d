module aes;

import deimos.openssl.aes;
import deimos.openssl.err;
import deimos.openssl.evp;
import deimos.openssl.ssl;
import std.base64;
import std.conv;
import std.exception;
import std.outbuffer;
import std.stdio;
import std.string;

/**
 * A custom exception to handle errors which happen when trying encypt/dycrypt
 */
class AESException : Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
    }
}

/// enc mode encrypt
static const(int) ENC_ENCRYPT = 1;
/// enc mode dycrypt
static const(int) ENC_DYCRYPT = 0;

/**
 * A structure around OpenSSL AES encryption
 */
struct AES {
    import deimos.openssl.rand : RAND_bytes;

    private EVP_CIPHER_CTX* ctx;
    private const(EVP_CIPHER*) mode;
    ubyte[] key;
    ubyte[] iv;

    // Initialize a secret key and initialization vector
    this(const(EVP_CIPHER*) mode, ubyte[] key, ubyte[] iv) {
        this.mode = mode;

        try {
            loadCipher(key, iv);
        }
        catch (AESException e) {
            throw e;
        }
    }

    // Initialize a secret key and initialization vector using strings
    this(const(EVP_CIPHER*) mode, string key, string iv) {
        this.mode = mode;

        try {
            loadCipher(stringToByte(key), stringToByte(iv));
        }
        catch (AESException e) {
            throw e;
        }
    }

    ~this() {
        EVP_CIPHER_CTX_free(this.ctx);
    }

    ubyte[] encrypt(string data) {
        if (EVP_CipherInit_ex(this.ctx, this.mode, null, this.key.dup.ptr,
                this.iv.dup.ptr, ENC_ENCRYPT) != 1) {
            throw new AESException("Failed to initiate cipher");
        }

        return applyCipher(data.dup);
    }

    string decrypt(ubyte[] data) {
        if (EVP_CipherInit_ex(this.ctx, this.mode, null, this.key.dup.ptr, this.iv.dup.ptr, ENC_DYCRYPT) != 1) {
            throw new AESException("Failed to initiate cipher");
        }

        OutBuffer buffer = new OutBuffer();
        buffer.write(applyCipher(data.dup));

        return buffer.toString();
    }

    private ubyte[] applyCipher(const ubyte[] data) {
        ubyte[] buffer;
        // TODO: Can we replace block size with key length
        const int bufferSize = cast(const(int)) (data.length + AES_BLOCK_SIZE - 1);
        int resultPtr;

        buffer.length = bufferSize;

        if (EVP_CipherUpdate(this.ctx, buffer.ptr, &resultPtr, data.ptr, data.length.to!int) != 1) {
            // TODO: This error message sucks
            throw new AESException("Failed to run CipherUpdate");
        }

        if (EVP_CipherFinal_ex(this.ctx, buffer.ptr + resultPtr, &resultPtr) != 1) {
            throw new AESException("Failed to run CipherFinal");
        }

        return buffer;
    }

    private ubyte[] applyCipher(char[] data) {
        // Cast to ubyte[] since that is what EVP is expecting
        const ubyte[] tempData = cast(const(ubyte)[]) data;
        return applyCipher(tempData);
    }

    private bool loadCipher(ubyte[] key, ubyte[] iv) {
        // Load the cipher
        EVP_add_cipher(this.mode);

        // Initialize the context
        this.ctx = EVP_CIPHER_CTX_new();

        // Initialize the cipher
        if (EVP_CipherInit_ex(this.ctx, this.mode, null, null, null, ENC_ENCRYPT) != 1) {
            throw new AESException("Error initializing cipher");
        }

        // Validate key
        if (key.length != EVP_CIPHER_CTX_key_length(this.ctx)) {
            throw new AESException(format("Invalid key length! Expected %d got %d",
                    EVP_CIPHER_CTX_key_length(this.ctx), key.length));
        }

        // Validate iv
        if (iv.length != EVP_CIPHER_CTX_iv_length(this.ctx)) {
            throw new AESException(format("Invalid IV length! Expected %d got %d",
                    EVP_CIPHER_CTX_iv_length(this.ctx), iv.length));
        }

        this.key = key;
        this.key.length = key.length;

        this.iv = iv;
        this.iv.length = iv.length;

        return true;
    }

    private ubyte[] stringToByte(string input) const {
        return cast(ubyte[]) input;
    }
}

@system unittest {
    // Make sure a valid cipher with correct length key/iv doesn't throw
    assertNotThrown!AESException(AES(EVP_aes_256_ctr(),
            "NfOfXOUTuZN1IaZA2s8n430QFr63x6gQ", "V7s860jZT8JMYkHD"));

    // Make sure a invalid cipher mode throws
    assertThrown!AESException(AES(null, "NfOfXOUTuZN1IaZA2s8n430QFr63x6gQ", "V7s860jZT8JMYkHD"));

    // Make sure a valid cipher with incorrect key throws
    assertThrown!AESException(AES(EVP_aes_256_ctr(), "notlong", "V7s860jZT8JMYkHD"));

    // Make sure a valid cipher with incorrect iv throws
    assertThrown!AESException(AES(EVP_aes_256_ctr(), "NfOfXOUTuZN1IaZA2s8n430QFr63x6gQ", "notlong"));
}

@system unittest {
    AES aes = AES(EVP_aes_256_ctr(), "NfOfXOUTuZN1IaYA2s8n430QFr63x6gQ", "V7s860jZT8JMYkHD");

    ubyte[] output = aes.encrypt("uerfgh");

    AES aes2 = AES(EVP_aes_256_ctr(), aes.key, aes.iv);
}
