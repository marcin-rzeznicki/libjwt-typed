# libjwt-typed

[![Build status](https://img.shields.io/travis/marcin-rzeznicki/libjwt-typed.svg?logo=travis)](https://travis-ci.org/marcin-rzeznicki/libjwt-typed)
[![Hackage](https://img.shields.io/hackage/v/libjwt-typed.svg?logo=haskell)](https://hackage.haskell.org/package/libjwt-typed)
[![Stackage Lts](http://stackage.org/package/libjwt-typed/badge/lts)](http://stackage.org/lts/package/libjwt-typed)
[![Stackage Nightly](http://stackage.org/package/libjwt-typed/badge/nightly)](http://stackage.org/nightly/package/libjwt-typed)
[![MPL-2.0 license](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

A Haskell implementation of [JSON Web Token (JWT)](https://jwt.io).

## Key features

### Type-safety

Above Haskell standard type-safety, the library keeps track of public and private claim names and types. There are no user-facing `HashMap`s in this library! A type of a JWT token might be: `Jwt
       '["user_name" ->> Text, "is_root" ->> Bool, "user_id" ->> UUID, "created" ->> UTCTime, "accounts" ->> NonEmpty (UUID, Text)]
       ('SomeNs "https://example.com")`.

From information encoded with precise types, it derives automatically serialization and deserialization. It can also work with generic representations such as records.

### Speed and robustness

`libjwt-typed` uses [libjwt](https://github.com/benmcollins/libjwt) for low-level functionality. `libjwt` delegates cryptographic work to either `GnuTLS` or `OpenSSL`. This way, not only the most performance-sensitive features work lightning fast, they are also extremely reliable.
Besides, the library does not depend on any JSON library like `aeson`, but it implements the necessary JSON processing in C via [jsmn](https://github.com/zserge/jsmn) - which makes it even faster.
[Benchmarking](#benchmarks) shows that it can be over 10 times faster than other Haskell JWT libraries.

### Ease of use

The library is designed for frictionless use. It can be easily extended, e.g. to add support for new types or to use custom JSON encodings compatible with other libraries you may already use in your project. Most instances can be derived automatically. The compilation errors are designed to be informational, i.e. you get `Claim "user_name" does not exist in this claim set` from GHC, not some 3 page long instance resolution output.

## Installation

`libjwt-typed` is available on [Hackage](http://hackage.haskell.org/package/libjwt-typed)

You must have `libjwt`  (preferrably the latest version) installed on your system and visible to the linker. `libjwt-typed` links to it at compile time. You can configure `libjwt` with `GnuTLS` or `OpenSSL` (it doesn't matter for `lbjwt-typed` which one you chose)

## Supported algorithms

|  JWS  | Algorithm | Description                        |
| :---: | :-------: | :--------------------------------- |
| HS256 |  HMAC256  | HMAC with SHA-256                  |
| HS384 |  HMAC384  | HMAC with SHA-384                  |
| HS512 |  HMAC512  | HMAC with SHA-512                  |
| RS256 |  RSA256   | RSASSA-PKCS1-v1_5 with SHA-256     |
| RS384 |  RSA384   | RSASSA-PKCS1-v1_5 with SHA-384     |
| RS512 |  RSA512   | RSASSA-PKCS1-v1_5 with SHA-512     |
| ES256 | ECDSA256  | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384  | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512  | ECDSA with curve P-521 and SHA-512 |


### Example usage

#### With secrets (HS256, HS384, HS512)

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Web.Libjwt ( Alg(HS512) )

hmac512 :: Alg
hmac512 =
  HS512
    "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\
    \YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\
    \Y2IwMDZhYWY1MjY1OTQgIC0K"
```

A key of the same size as the hash output (for instance, 256 bits for
   "HS256") or larger MUST be used with these algorithms.

#### With keys 

Obtaining or reading keys is beyond the scope of this library. It accepts PEM-encoded RSA/ECDSA keys as `ByteString`s

```haskell
import           Web.Libjwt                     ( Alg(..)
                                                , EcKeyPair(..)
                                                , RsaKeyPair(..)
                                                )
import qualified Data.ByteString.Char8         as C8

rsa2048KeyPair :: RsaKeyPair
rsa2048KeyPair =
  let private = C8.pack $ unlines
        [ "-----BEGIN RSA PRIVATE KEY-----"
        , "MIIEpgIBAAKCAQEAwCXp2P+qboao0tjUyU+D3YI+sgBn8dkGaxOvPFLBFQMNkhbL"
        -- ... 
        , "-----END RSA PRIVATE KEY-----"
        ]
      public = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCXp2P+qboao0tjUyU+D"
        -- ...
        , "-----END PUBLIC KEY-----"
        ]
  in  FromRsaPem { privKey = private, pubKey = public }

rs512 :: Alg
rs512 = RS512 rsa2048KeyPair

ecP521KeyPair :: EcKeyPair
ecP521KeyPair =
  let private = C8.pack $ unlines
        [ "-----BEGIN EC PRIVATE KEY-----"
        , "MIHcAgEBBEIAIWLn8LIw+NC3gZJIFemY/Ku5QNNncVjNZiQdICh7KzgHPrjCrdQk"
        -- ...
        , "-----END EC PRIVATE KEY-----"
        ]
      public = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBoCA7tBSz6R9DTQM5aq0VtyApXMUm"
        -- ...
        , "-----END PUBLIC KEY-----"
        ]
  in  FromEcPem { ecPrivKey = private, ecPubKey = public }

es512 :: Alg
es512 = ES512 ecP521KeyPair
```

A key of size 2048 bits or larger MUST be used for RSA algorithms.

The [specification](https://tools.ietf.org/html/rfc7518) defines "the use of ECDSA with the P-256 curve [secp256k1 or prime256v1] and
   the SHA-256 cryptographic hash function, ECDSA with the P-384 curve [secp384r1]
   and the SHA-384 hash function, and ECDSA with the P-521 curve [secp521r1] and the
   SHA-512 hash function."

## Usage 

### Create a payload

Assuming

```haskell
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NoMonomorphismRestriction #-} -- just for sweet and short examples
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

import           Web.Libjwt

import           Data.ByteString                ( ByteString )
import           Data.Default
import           Data.List.NonEmpty             ( NonEmpty(..) )
import           Data.Text                      ( Text )
import           Data.Time.Clock                ( UTCTime )
import           Data.UUID                      ( UUID )
import           GHC.Generics

import           Prelude                 hiding ( exp )

data UserClaims = UserClaims { userId :: UUID
                             , userName :: Text
                             , isRoot :: Bool
                             , createdAt :: UTCTime
                             , accounts :: NonEmpty UUID
                             }
  deriving stock (Eq, Show, Generic)
```

* Direct style
```haskell

mkPayload UserClaims {..} currentTime =
  let now = fromUTC currentTime
  in  def
        { iss           = Iss (Just "myApp")
        , aud           = Aud ["https://myApp.com"]
        , iat           = Iat (Just now)
        , exp           = Exp (Just $ now `plusSeconds` 300)
        , privateClaims = toPrivateClaims
                            ( #user_name ->> userName
                            , #is_root ->> isRoot
                            , #user_id ->> userId
                            , #created ->> createdAt
                            , #accounts ->> accounts
                            )
        }

{-
λ> :t mkPayload
mkPayload
  :: UserClaims
     -> UTCTime
     -> Payload
          '["user_name" ->> Text, "is_root" ->> Bool, "user_id" ->> UUID,
            "created" ->> UTCTime, "accounts" ->> NonEmpty UUID]
          'NoNs 
-}

```

* Builder (monoidal) style
```haskell

mkPayload' UserClaims {..} = jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  ( #user_name ->> userName
  , #is_root ->> isRoot
  , #user_id ->> userId
  , #created ->> createdAt
  , #accounts ->> accounts
  )

{-
λ> :t mkPayload'
mkPayload'
  :: MonadTime m =>
     UserClaims
     -> m (Payload
             '["user_name" ->> Text, "is_root" ->> Bool, "user_id" ->> UUID,
               "created" ->> UTCTime, "accounts" ->> NonEmpty UUID]
             'NoNs)
-}

```

* Generic style
```haskell

instance ToPrivateClaims UserClaims

mkPayload'' = jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  UserClaims { userId    = read "5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25"
             , userName  = "JohnDoe"
             , isRoot    = False
             , createdAt = read "2020-07-31 11:45:00 UTC"
             , accounts  = read "0bdf91cc-48bb-47f5-b633-920c34bd2352" :| []
             }

```

#### Namespaces

To ensure that private do not collide with claims from other resources, it is recommended to give them globally unique names . This is often done through _namespacing_, i.e. prefixing the names with the URI of a resource you control. In `libjwt-typed` this is handled entirely at the type-level, and you don't need to write any code to handle this case. As you may have noticed, `Payload` types have a component of the type `NoNs`. It tracks the namespace assigned to private claims within this payload. If you change the last example to:

```haskell
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

mkPayload''' =
  jwtPayload
      (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
    $ withNs
        (Ns @"https://myApp.com")
        UserClaims
          { userId    = read "5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25"
          , userName  = "JohnDoe"
          , isRoot    = False
          , createdAt = read "2020-07-31 11:45:00 UTC"
          , accounts  = read "0bdf91cc-48bb-47f5-b633-920c34bd2352" :| []
          }
```

, you'll notice that the type has changed to accomodate the namespace (becoming `Payload '[...] ('SomeNs "https://myApp.com")`). Consequently, in the generated token `"userId"` becomes `"https://myApp.com/userId"` etc

### Signing a token

```haskell

token :: IO ByteString -- or any other MonadTime instance
token = do
  payload <- mkPayload''
  return $ getToken $ signJwt Jwt { header = Header { alg = hmac512, typ = JWT }
                                  , payload = payload
                                  }

{-
λ> token
"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50cyI6WyIwYmRmOTFjYy00OGJiLTQ3ZjUtYjYzMy05MjBjMzRiZDIzNTIiXSwiYXVkIjpbImh0dHBzOi8vbXlBcHAuY29tIl0sImNyZWF0ZWRBdCI6IjIwMjAtMDctMzFUMTE6NDU6MDBaIiwiZXhwIjoxNTk5NDk5MDczLCJpYXQiOjE1OTk0OTg3NzMsImlzUm9vdCI6ZmFsc2UsImlzcyI6Im15QXBwIiwidXNlcklkIjoiNWE3YzVjZGQtMzkwOS00NTZiLTlkZDItNmJhODRiZmVlYjI1IiwidXNlck5hbWUiOiJKb2huRG9lIn0.KH4YSODoTxuNLPYCyz0lmoVDHYJpvL8k6fccFugqs-6VcpctXeR4OYyWOZJDi294r6njCqRP15eqYpwrrzKKrQ" 
-}

```

Tip: you can inspect the above token in the [JWT debugger](https://jwt.io)

`signJwt` is a pure function, we only need `Monad` for the `currentTime` used to construct the payload.

### Decoding a token

```haskell

{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}

type MyJwt
  = Jwt
      '["userId" ->> UUID, "userName" ->> Text, "isRoot" ->> Bool, "createdAt" ->> UTCTime, "accounts" ->> NonEmpty UUID]
      'NoNs

decodeDoNotUse :: IO (Decoded MyJwt)
decodeDoNotUse = decodeByteString hmac512 =<< token

{-
λ> decode_do_not_use
MkDecoded {getDecoded = Jwt {header = Header {alg = HS512 (MkSecret {reveal = "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2MxYzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5Y2IwMDZhYWY1MjY1OTQgIC0K"}), typ = JWT}, payload = ClaimsSet {iss = Iss (Just "myApp"), sub = Sub Nothing, aud = Aud ["https://myApp.com"], exp = Exp (Just (NumericDate {secondsSinceEpoch = 1599501809})), nbf = Nbf Nothing, iat = Iat (Just (NumericDate {secondsSinceEpoch = 1599501509})), jti = Jti Nothing, privateClaims = (#userId ->> 5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25, #userName ->> "JohnDoe", #isRoot ->> False, #createdAt ->> 2020-07-31 11:45:00 UTC, #accounts ->> (0bdf91cc-48bb-47f5-b633-920c34bd2352 :| []))}}}
-}

```

While the structure of the JWT can be inferred when signing - this obviously is not the case when decoding. `decodeByteString` can't possibly know what you are going to extract from the token, so you need to give it the expected type. It can simply be _type-alias_ like in the example above. Based on this, the correct deserialization is dervied. If something goes wrong an exception will be thrown, which you can catch and inspect. 

The result of this function is an instance of `Decoded` type. The JWT stucture wrapped in this type is guaranteed to be correct representation of the requested type with its signature checked according to your algorithm and secret/key.

**IMPORTANT: Your program should always require an instance of the `Validated` type (see below). `Decoded` only means that the signature and the representation are correct, but does not verify that the token has not expired or is not intended for you etc.**

To return decoded **and** validated structure it is better to do

```haskell

decodeAndValidate :: IO (ValidationNEL ValidationFailure (Validated MyJwt))
decodeAndValidate = jwtFromByteString settings mempty hmac512 =<< token
  where settings = Settings { leeway = 5, appName = Just "https://myApp.com" }

{-
λ> decodeAndValidate 
Success (MkValid {getValid = Jwt {header = Header {alg = HS512 (MkSecret {reveal = "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2MxYzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5Y2IwMDZhYWY1MjY1OTQgIC0K"}), typ = JWT}, payload = ClaimsSet {iss = Iss (Just "myApp"), sub = Sub Nothing, aud = Aud ["https://myApp.com"], exp = Exp (Just (NumericDate {secondsSinceEpoch = 1599504161})), nbf = Nbf Nothing, iat = Iat (Just (NumericDate {secondsSinceEpoch = 1599503861})), jti = Jti Nothing, privateClaims = (#userId ->> 5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25, #userName ->> "JohnDoe", #isRoot ->> False, #createdAt ->> 2020-07-31 11:45:00 UTC, #accounts ->> (0bdf91cc-48bb-47f5-b633-920c34bd2352 :| []))}}})
 -}

```

JWT validation is monoid. You can append additional validations based on public and private claims, for example `checkIssuer "myApp" <> checkClaim (== True) #isRoot`. You will certainly like the fact that private claims' types are fullly known, so you can operate on type-safe Haskell values (`checkClaim ( > 0) #isRoot` will not compile). The `mempty` validation (the default validation) checks (according to [the rules in the RFC](https://tools.ietf.org/html/rfc7519#section-4.1) ) whether:
* token has not expired (`exp` claim),
* token is ready to use (`nbf` claim),
* token is intended for you (`aud` claim)
  
Time-based validations (all predefined validations for `exp`, `nbf` and `iat` claims) allow for some small leeway (e.g. `leeway = 5` means that the token expired less than 5 seconds ago is still considered to be valid), which can be set in `ValidationSettings`.

Full example with error-handling might look like:
```haskell
{-# LANGUAGE ScopedTypeVariables #-}

import           Control.Arrow                  ( left )
import           Control.Exception              ( catch
                                                , displayException
                                                )
import           Data.Either.Validation         ( validationToEither )

decodeAndValidateFull :: IO (Either String UserClaims)
decodeAndValidateFull =
  (   left (("Token not valid: " ++) . show)
    .   fmap toUserClaims
    .   validationToEither
    <$> decodeAndValidate
    )
    `catch` onError
 where
  toUserClaims = fromPrivateClaims . privateClaims . payload . getValid
  onError (e :: SomeDecodeException) =
    return $ Left $ "Cannot decode token " ++ displayException e

{-
λ> decodeAndValidateFull 
Right (UserClaims {userId = 5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25, userName = "JohnDoe", isRoot = False, createdAt = 2020-07-31 11:45:00 UTC, accounts = 0bdf91cc-48bb-47f5-b633-920c34bd2352 :| []})
-}

```

## Benchmarks

Full result sets (graphical HTML reports) are available [here](https://github.com/marcin-rzeznicki/libjwt-typed/tree/master/bench/results). 

Code can be found [here](https://github.com/marcin-rzeznicki/libjwt-typed/tree/master/bench). Benchmarking is undoubtedly hard - if you think something can be improved, please make a PR.

The Benchmarks compare `libjwt-typed` to `jose` in different hopefully real-world use cases. All the results below were obtained on a 6-Core Intel Core i7-9750H; 32 GB RAM; GHC 8.10.1 (compiled with -O2; RTS options: -N -ki2k -A512m -n32m); libjwt built with GnuTLS using GCC 10.2.0

### Signing

Measuring going from data to a fully signed, ready to send down-the-wire token

When signing an "empty" token using `SHA-512` i.e. something like
```json
{
  "iat": 1599531131,
  "nbf": 1599531131,
  "exp": 1599531431,
  "sub": "c5caab61-3ee4-49ab-86e6-b6ac292901f7",
  "aud": ["https://example.com"],
  "iss": "benchmarks"
}
```

| what  |                libjwt                 |               jose                | speedup |
| :---: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean  | **9.920 μs**   (9.834 μs .. 10.01 μs) | 183.4 μs   (181.8 μs .. 185.4 μs) |   18x   |

For more complex tokens i.e. something like
```json
{
  "iat": 1599531131,
  "nbf": 1599531131,
  "exp": 1599531431,
  "sub": "c5caab61-3ee4-49ab-86e6-b6ac292901f7",
  "aud": ["https://example.com"],
  "iss": "benchmarks",
  "user_name": "E\\129057~[lzR64FhhdhrlUMH0A",
  "is_root": true,
  "client_id": "b659f842-5d78-4da1-9891-8aaa4ac3983b",
  "created": "2020-09-08 02:12:11.099106573 UTC",
  "accounts": [
    ["8aa634fb-8cc4-44cb-84ec-9eb6c78834e1", "k"],
    ["da8b0ff6-a32c-43d0-bd89-1a63273945e0", ")`"],
    ["219f30da-c474-4f23-af6a-495b1034e02f", "J"]
  ],
  "emails": ["0g(B@example.com", "eo@example.com"]
}
```

| what  |                libjwt                 |               jose                | speedup |
| :---: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean  | **38.71 μs**   (38.63 μs .. 38.84 μs) | 603.7 μs   (600.8 μs .. 606.6 μs) |   15x   |


When signing using elliptic-curve cryptography: `ECDSA256` 

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **86.73 μs**   (86.65 μs .. 86.84 μs) | 1.310 ms   (1.307 ms .. 1.313 ms) |   15x   |
| mean (complex) | **125.7 μs**   (125.5 μs .. 125.9 μs) | 1.711 ms   (1.709 ms .. 1.714 ms) |   13x   |

and `ECDSA512`

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **303.6 μs**   (303.3 μs .. 303.8 μs) | 4.435 ms   (4.426 ms .. 4.444 ms) |   14x   |
| mean (complex) | **342.2 μs**   (342.0 μs .. 342.5 μs) | 4.632 ms   (4.625 ms .. 4.641 ms) |   13x   |

And finally using the `RSA (RSASSA-PKCS1-v1_5 using SHA-512)`

|      what      |              libjwt               |                 jose                  | speedup |
| :------------: | :-------------------------------: | :-----------------------------------: | :-----: |
| mean (simple)  | 1.576 ms   (1.576 ms .. 1.577 ms) | **1.156 ms**   (1.154 ms .. 1.159 ms) |  0.7x   |
| mean (complex) | 1.627 ms   (1.625 ms .. 1.628 ms) | **1.542 ms**   (1.539 ms .. 1.547 ms) |  0.9x   |

This is the only time `jose` is faster (congrats!). `libjwt-typed` is slower probably because it doesn't store private key parameters. This is something thaht needs to be improved.

### Decoding

Here going from a `ByteString` token back to the data is measured. When I say "to the data" I mean user-types, not `aeson` values. This is where `libjwt-typed` has considerable leverage as it doesn't use any intermediate form, but I think it is fair as users will eventually have to parse data anyway.

Using `HMAC512`

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **10.19 μs**   (10.14 μs .. 10.23 μs) | 141.4 μs   (140.4 μs .. 142.2 μs) |   13x   |
| mean (complex) | **68.47 μs**   (68.25 μs .. 68.66 μs) | 294.3 μs   (293.2 μs .. 295.9 μs) |   4x    |

Using `ECDSA256`

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **214.4 μs**   (214.1 μs .. 215.6 μs) | 1.445 ms   (1.442 ms .. 1.448 ms) |   6x    |
| mean (complex) | **278.4 μs**   (278.2 μs .. 278.7 μs) | 1.716 ms   (1.714 ms .. 1.720 ms) |   6x    |

Using `ECDSA512`

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **860.3 μs**   (859.0 μs .. 862.4 μs) | 4.986 ms   (4.978 ms .. 4.992 ms) |   5x    |
| mean (complex) | **908.1 μs**   (907.5 μs .. 909.5 μs) | 5.185 ms   (5.181 ms .. 5.192 ms) |   5x    |

And finally `RSA`

|      what      |                libjwt                 |               jose                | speedup |
| :------------: | :-----------------------------------: | :-------------------------------: | :-----: |
| mean (simple)  | **44.64 μs**   (44.62 μs .. 44.68 μs) | 150.7 μs   (149.8 μs .. 151.5 μs) |   3x    |
| mean (complex) | **104.9 μs**   (104.8 μs .. 105.1 μs) | 456.4 μs   (454.8 μs .. 458.0 μs) |   4x    |

## Idea

The idea for this lib comes from my talk ["Building a web library using super hard Haskell"](https://www.youtube.com/watch?v=icgl9FuPxKA) at the Haskell Love Conference