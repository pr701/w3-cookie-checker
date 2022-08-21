/*
*	protobuf authentication utils
*	pr, 2022
*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef __authentication_utils__
#define __authentication_utils__

#include <cstdint>
#include <string>
#include <vector>

#include <botan/secmem.h>
#include <botan/pbkdf2.h>
#include <botan/hash.h>
#include <botan/base64.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/rsa.h>
#include <botan/cryptobox.h>

#include <botan/bigint.h>
#include <botan/numthry.h>

#include "authentication.pb.h"

typedef Botan::secure_vector<uint8_t> bytes_t;

namespace detail
{
    const char* k_d2r_connection = "classic.protocol.v1.d2r_connection.AuthSessionResponse";
}

namespace classic {
namespace protocol {
namespace v1 {
namespace authentication {

    enum app_id
    {
        D2 = 'OSI',
        S1 = 'S1',
        W3 = 'W3',
    };

    enum class decrypt_error
    {
        success_decrypt = 0,
        mismatched_protobuf_types = 1,
        invalid_decryption_key = 2,
        parse_protobuf_error = 3,
    };

    inline bool verify_cookie(const OfflineCookie& cookie)
    {
        const char* publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8of3JLclDeK3T0q6l5XL"
            "4IOHEVTmtMId2fzeUyp9lEx7Gg+gj6QQ4hYZrNdu8PsJk7CiXL/K5yed59zEuJBn"
            "2F/53twKSQsmoDAINtt8fSKRGbzdWiztr8rXYYc7FuwsCA+SOxPtRZZ/rA+trv3V"
            "3L0JNmkcwGlu0a5OLDcK+4kWVOp4f5A9VN62CCFCLmdyU6VJ1gUlSVaRUR3wT0eG"
            "g7EQgFfrDwPgBrtZ3x6K3RDa7hgOZ3+94Qw4qZsfQUBppDR8N/Me2A/n1jJ3JGee"
            "tdJ/e/pZehpf64ap57xzOLiZkfOexniR5ktcVKAUNn/JGpSrKhry/jeZi8p2Dfet"
            "3wIDAQAB";

        auto der = Botan::base64_decode(publicKey);
        auto rsaPub = Botan::X509::load_key(std::vector<uint8_t>(der.begin(), der.end()));

        Botan::PK_Verifier verifier(*rsaPub, "EMSA1(SHA-224)");

        auto sign = cookie.signature();
        verifier.update(cookie.proto_payload());
        return verifier.check_signature((uint8_t*)sign.data(), sign.size());
    }

    inline decrypt_error decrypt_cookie(const OfflineCookie& cookie, const std::string& hwid,
        AuthSessionResponse& response)
    {
        if (cookie.game_id() == app_id::D2)
        {
            if (cookie.proto_name().compare(std::string(detail::k_d2r_connection)))
                return decrypt_error::mismatched_protobuf_types;
        }
        else
        {
            if (response.GetTypeName().compare(cookie.proto_name()))
                return decrypt_error::mismatched_protobuf_types;
        }

        bytes_t payload;
        try
        {
            std::string crypted =
                "-----BEGIN BOTAN CRYPTOBOX MESSAGE-----\n" +
                cookie.proto_payload() +
                "\n-----END BOTAN CRYPTOBOX MESSAGE-----\n";
            payload = Botan::CryptoBox::decrypt_bin(crypted, hwid);
        }
        catch (const std::exception& e)
        {
            return decrypt_error::invalid_decryption_key;
        }
        return response.ParseFromArray(payload.data(), payload.size()) ?
            decrypt_error::success_decrypt : decrypt_error::parse_protobuf_error;
    }

    inline std::string app_id_to_name(int64_t game_id)
    {
        switch (game_id)
        {
        case app_id::D2:
            return "Diablo II: Resurrected";
        case app_id::S1:
            return "StarCraft: Remastered";
        case app_id::W3:
            return "Warcraft III: Refunded";
        default:
            return "Unknown Title";
        }
    }
}
}
}
}

#endif
