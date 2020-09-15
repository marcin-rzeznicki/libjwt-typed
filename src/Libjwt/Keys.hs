--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}

-- | Keys used for signing and validation
module Libjwt.Keys
  ( Secret(..)
  , RsaKeyPair(..)
  , EcKeyPair(..)
  )
where

import           Data.ByteString                ( ByteString )

import qualified Data.ByteString.UTF8          as UTF8

import           Data.String

-- | Secret used in /HMAC/ algorithms.
-- 
--   According to RFC:
--   /A key of the same size as the hash output (for instance, 256 bits for 'HS256') or larger MUST be used (...)/ 
--   - the user must ensure this property holds.
--
--   A secret is just an octet sequence e.g.
--
-- @
-- hs512 =
--  HS512
--    "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\\
--    \\YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\\
--    \\Y2IwMDZhYWY1MjY1OTQgIC0K"
-- @
newtype Secret = MkSecret { reveal :: ByteString }
  deriving stock (Show, Eq)

instance IsString Secret where
  fromString = MkSecret . UTF8.fromString

-- | RSA key-pair used in /RSA/ algorithms
--
--   According to RFC:
--   /A key of size 2048 bits or larger MUST be used with these algorithms./ 
--   - the user must ensure this property holds.
--
--   Both fields are assumed to be strings representing /PEM-encoded/ keys
--
-- >
-- >rsa2048KeyPair =
-- >  let private = C8.pack $ unlines
-- >        [ "-----BEGIN RSA PRIVATE KEY-----"
-- >        , "MIIEpgIBAAKCAQEAwCXp2P+qboao0tjUyU+D3YI+sgBn8dkGaxOvPFLBFQMNkhbL"
-- >        , "0HEoRKNnQCubZNc0jXnMK5hCeGRnDS7lYclROXocRWUn5s2W3jP5xn7lM4otIpuE"
-- >        , "3FStthMCrPSEQiBCXE4cyKiHaZqmbqXlHAHVEuGMM7oddiB6s3zjwf2h1v0SEiHf"
-- >        , "5ZFzTVarStablqh6wVDAiYyM+8aUM0x9p3JcaWW+eDk/UU3jCfCke7R3t2rbD1ZC"
-- >        , "j1cO08Uir3Lhf65TfU+iIrgLU3umV4B3gRcpd8iz0ZTLaG8Qnm0GsPQjR3PTZYEC"
-- >        , "xEnFaRgXcQLHYYMAW9YaX6T3rlTGZAaP5YboxQIDAQABAoIBAQCg/OMBsauc8Ovv"
-- >        , "xEX76MglxeM7hgWQ5vFus05lrzwgm686EClxme1QHMv8QszuXzSjuEFs4SQH9K82"
-- >        , "p2z+UgrgqkOXjNoykVvvDgMe4OCuHv4T+dMGO1hTrXfXawKI2Lhg1/1bzX+u5ii9"
-- >        , "mfbsUUixihHKoQvgFfRX/7JfrV50XZ3diwzd8DoEaIgeAIdyhLhVuh2W7wXbOF+l"
-- >        , "aZW7gqCVzTBhC04E/D6eqFqvnkQyHzZPgaaDi4oL7gP8nGpcswlqKSLO5eVkkEHY"
-- >        , "C88nAwU4Q/+qcAf09ijmTLlo07xLrLC0cOf2yQTwLj6ZffzTJ7NSMaPrTdEXThsW"
-- >        , "wAeB/GcBAoGBAOzLST9/zakFGBTkwiLqgNVgEBUoYjB0Z+Fpx4qBLzKZNQP1yNup"
-- >        , "LhC/4pIVQM+ZjOS0Wx7Sh0FTLHFb018quPiAPsKMEC2CW5v7vKwC4zW72/v5UrIw"
-- >        , "pcBzl67nsc53r5Lblol9PU4oCjDzuFMjMbg+EzD3kVp/gxC9bRMwK3zBAoGBAM+7"
-- >        , "nOV80uteB1ZXazccj6g0ANd2AyJY6gHfxD1CopvRReYm36wmG00HQ3jHZPUcsLQp"
-- >        , "dWvWplRFprZlce0jl7HcB/8g5wUkErMop3KK5cA886HxsATNSl6rYghZGALqxm/a"
-- >        , "+v2AKoZThns8QRYL5bsBD4kTQLEIwp7j6sNbBrkFAoGBAL6fL8o0gkUsWqSHO1mM"
-- >        , "WkZrXMcLiW/kZbPqyb3QHUSoXStg818RpInLTwO2pEP7IpcCMdBwPn3yDPb8qv4T"
-- >        , "kHBMHTnUMznPlRvO3aXDdVFOd9sybMYRr31sEJG250aExwx8RYVNEssWJI4fxST4"
-- >        , "UhA1uJFU2uh1efdB5srpnjiBAoGBALTDCPAZAmCVXcUgJMe8LrWrKuBSbL/Cpz4i"
-- >        , "PV0hUuZL4Is5YIEoV7FblLbQq2UvJgRf3zGLgwjp4vvsooo74pB+auby9pReo3cK"
-- >        , "9UqS2wHBCC/vY7+J9CEU+SVSgbZoHWzQHH/iux5QKEGsWOaaS7nCXoZlHnHusYwZ"
-- >        , "v/tmhh8RAoGBAIi3Lbup0AVwougANLXwMLCfT8HxI8Hozdr+Pe0ibTnjfY+BPuy1"
-- >        , "vSgozXao68TwW3u58PcdvfBnfg/7XCK6TXtij48JDu6qw0IiSRxOZ5Ed/GW2P031"
-- >        , "7TfwnjBohjM2O6NRne8qe6Qv5xLagoVKQfa1WhQEFU2bTNLYA/2kv266"
-- >        , "-----END RSA PRIVATE KEY-----"
-- >        ]
-- >      public = C8.pack $ unlines
-- >        [ "-----BEGIN PUBLIC KEY-----"
-- >        , "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCXp2P+qboao0tjUyU+D"
-- >        , "3YI+sgBn8dkGaxOvPFLBFQMNkhbL0HEoRKNnQCubZNc0jXnMK5hCeGRnDS7lYclR"
-- >        , "OXocRWUn5s2W3jP5xn7lM4otIpuE3FStthMCrPSEQiBCXE4cyKiHaZqmbqXlHAHV"
-- >        , "EuGMM7oddiB6s3zjwf2h1v0SEiHf5ZFzTVarStablqh6wVDAiYyM+8aUM0x9p3Jc"
-- >        , "aWW+eDk/UU3jCfCke7R3t2rbD1ZCj1cO08Uir3Lhf65TfU+iIrgLU3umV4B3gRcp"
-- >        , "d8iz0ZTLaG8Qnm0GsPQjR3PTZYECxEnFaRgXcQLHYYMAW9YaX6T3rlTGZAaP5Ybo"
-- >        , "xQIDAQAB"
-- >        , "-----END PUBLIC KEY-----"
-- >        ]
-- >  in  FromRsaPem { privKey = private, pubKey = public }
data RsaKeyPair = FromRsaPem { privKey :: ByteString, pubKey :: ByteString }
  deriving stock (Show, Eq)

-- | Elliptic curves parameters used in /ECDSA/ algorithms
--
--   According to RFC, the following curves are to be used:
--
--  +-------------------+-------------------------------+
--  | "alg" Param Value | Digital Signature Algorithm   |
--  +===================+===============================+
--  | ES256             | ECDSA using P-256 and SHA-256 |
--  +-------------------+-------------------------------+
--  | ES384             | ECDSA using P-384 and SHA-384 |
--  +-------------------+-------------------------------+
--  | ES512             | ECDSA using P-521 and SHA-512 |
--  +-------------------+-------------------------------+
--
--  It is up to the user to use the appropriate curves.
--
--  The following names are used in OpenSSL: /prime256v1/, /secp384r1/ and /secp521r1/
--
--  Curve parametrs should be /PEM-encoded/ strings
--
-- > ecP256KeyPair =
-- >   let private = C8.pack $ unlines
-- >         [ "-----BEGIN EC PRIVATE KEY-----"
-- >         , "MHcCAQEEINQ0e0KOa3EZSB5RTd2xBuO3O7NNFietDIWl+B+R38LuoAoGCCqGSM49"
-- >         , "AwEHoUQDQgAEKZL0X84AvdnGZdsIdAS60OnvF3FNlsrCnaXRoJUVdOYZldzb4po2"
-- >         , "uDXF5W58DS8C31fV+z+0lTG5RvuAqfkdbA=="
-- >         , "-----END EC PRIVATE KEY-----"
-- >         ]
-- >       public = C8.pack $ unlines
-- >         [ "-----BEGIN PUBLIC KEY-----"
-- >         , "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKZL0X84AvdnGZdsIdAS60OnvF3FN"
-- >         , "lsrCnaXRoJUVdOYZldzb4po2uDXF5W58DS8C31fV+z+0lTG5RvuAqfkdbA=="
-- >         , "-----END PUBLIC KEY-----"
-- >         ]
-- >   in  FromEcPem { ecPrivKey = private, ecPubKey = public }
data EcKeyPair = FromEcPem { ecPrivKey :: ByteString, ecPubKey :: ByteString }
  deriving stock (Show, Eq)
