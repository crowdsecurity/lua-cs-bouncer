local ffi = require("ffi")

ffi.cdef[[
    typedef struct engine_st ENGINE;
    typedef struct evp_md_st EVP_MD;
    typedef struct evp_md_ctx_st EVP_MD_CTX;

    const EVP_MD *EVP_sha256(void);
    unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                        const unsigned char *d, size_t n, unsigned char *md,
                        unsigned int *md_len);
    unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
]]

local M = {}

-- Helper conversion Binaire -> Hexadécimal
local function to_hex(raw_bytes, len)
    local hex = {}
    for i = 0, len - 1 do
        table.insert(hex, string.format("%02x", raw_bytes[i]))
    end
    return table.concat(hex)
end

-- SHA256 FFI direct OpenSSL
local function sha256_hex(data)
    local md = ffi.new("unsigned char[32]")
    ffi.C.SHA256(data, #data, md)
    return to_hex(md, 32)
end

-- HMAC-SHA256 FFI direct OpenSSL
local function hmac_sha256(key, data)
    local md = ffi.new("unsigned char[32]")
    local md_len = ffi.new("unsigned int[1]")
    local evp_sha256 = ffi.C.EVP_sha256()
    
    ffi.C.HMAC(evp_sha256, key, #key, data, #data, md, md_len)
    return to_hex(md, 32)
end

-- 1. Création du challenge
function M.create_challenge(secret, max_number)
    max_number = max_number or 50000
    local raw_salt = ngx.encode_base64(ngx.time() .. math.random(1000, 9999))
    local salt = sha256_hex(raw_salt):sub(1, 16)
    
    local number = math.random(0, max_number)
    local challenge_str = salt .. tostring(number)
    local challenge = sha256_hex(challenge_str)

    local signature = hmac_sha256(secret, challenge)

    return {
        algorithm = "SHA-256",
        challenge = challenge,
        salt = salt,
        signature = signature,
        maxnumber = max_number
    }
end

-- 2. Vérification du payload
function M.verify_payload(secret, payload_base64)
    if not payload_base64 or payload_base64 == "" then
        return false, "payload missing"
    end

    local decoded = ngx.decode_base64(payload_base64)
    if not decoded then
        return false, "invalid base64"
    end

    local cjson = require("cjson")
    local ok, data = pcall(cjson.decode, decoded)
    if not ok or type(data) ~= "table" then
        return false, "invalid json payload"
    end

    local expected_signature = hmac_sha256(secret, data.challenge)
    if expected_signature ~= data.signature then
        return false, "invalid signature"
    end

    local computed_hash = sha256_hex(data.salt .. tostring(data.number))
    if computed_hash ~= data.challenge then
        return false, "invalid pow solution"
    end

    return true, nil
end

return M
