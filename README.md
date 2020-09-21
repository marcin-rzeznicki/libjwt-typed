# libjwt-typed

[![Build status](https://travis-ci.com/marcin-rzeznicki/libjwt-typed.svg?branch=master)](https://travis-ci.org/marcin-rzeznicki/libjwt-typed)
[![Hackage](https://img.shields.io/hackage/v/libjwt-typed.svg?logo=haskell)](https://hackage.haskell.org/package/libjwt-typed)
[![Stackage Lts](http://stackage.org/package/libjwt-typed/badge/lts)](http://stackage.org/lts/package/libjwt-typed)
[![Stackage Nightly](http://stackage.org/package/libjwt-typed/badge/nightly)](http://stackage.org/nightly/package/libjwt-typed)
[![MPL-2.0 license](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

A Haskell implementation of [JSON Web Token (JWT)](https://jwt.io).

1. [Key features](#key-features)
   1. [Type-safety](#type-safety)
   1. [Speed and robustness](#speed-and-robustness)
   1. [Ease of use](#ease-of-use)
1. [Installation](#installation)
1. [Supported algorithms](#supported-algorithms)
   1. [Example usage](#example-usage)
      1. [With secrets (HS256, HS384, HS512)](#with-secrets-hs256-hs384-hs512)
      1. [With keys](#with-keys)
1. [Usage](#usage)
   1. [Create a payload](#create-a-payload)
      1. [Namespaces](#namespaces)
   1. [Signing a token](#signing-a-token)
   1. [Decoding a token](#decoding-a-token)
1. [Supported types](#supported-types)
   1. [Flags](#flags)
1. [Benchmarks](#benchmarks)
   1. [Signing](#signing)
   1. [Decoding](#decoding)
1. [Not implemented](#not-implemented)
1. [Idea](#idea)

## Key features

### Type-safety

Above Haskell standard type-safety, the library keeps track of public and private claim names and types. There are no user-facing `HashMap`s in this library! A type of a JWT token might be: `Jwt
       '["user_name" ->> Text, "is_root" ->> Bool, "user_id" ->> UUID, "created" ->> UTCTime, "accounts" ->> NonEmpty (UUID, Text)]
       ('SomeNs "https://example.com")`.

From information encoded with precise types, it automatically derives encoders and decoders. It can also work with generic representations such as records.

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

import Web.Libjwt

hmac512 :: Algorithm Secret
hmac512 =
  HMAC512
    "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\
    \YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\
    \Y2IwMDZhYWY1MjY1OTQgIC0K"
```

A key of the same size as the hash output (for instance, 256 bits for
   "HS256") or larger MUST be used with these algorithms.

#### With keys 

Obtaining or reading keys is beyond the scope of this library. It accepts PEM-encoded RSA/ECDSA keys as `ByteString`s

```haskell
import           Web.Libjwt

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

rsa512 :: Algorithm RsaKeyPair
rsa512 = RSA512 rsa2048KeyPair

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

ecdsa512 :: Algorithm EcKeyPair
ecdsa512 = ECDSA512 ecP521KeyPair
```

A key of size 2048 bits or larger MUST be used for RSA algorithms.

The [specification](https://tools.ietf.org/html/rfc7518) defines "the use of ECDSA with the P-256 curve [secp256k1 or prime256v1] and
   the SHA-256 cryptographic hash function, ECDSA with the P-384 curve [secp384r1]
   and the SHA-384 hash function, and ECDSA with the P-521 curve [secp521r1] and the
   SHA-512 hash function."

As of version **0.2**, you do not need private keys as long as you only decode tokens. This is obviously a type-safe feature, so you cannot pass a public-key to the signing function.
Type system checks it for you.

```haskell
import           Web.Libjwt

import qualified Data.ByteString.Char8         as C8

rsaPub :: RsaPubKey
rsaPub =
  let public = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCXp2P+qboao0tjUyU+D"
        -- ...
        , "-----END PUBLIC KEY-----"
        ]
  in  FromRsaPub { rsaPublicKey = public }

rsa512 :: Algorithm RsaPubKey
rsa512 = RSA512 rsaPub
```

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
token = getToken . sign hmac512 <$> mkPayload''

{-
λ> token
"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50cyI6WyIwYmRmOTFjYy00OGJiLTQ3ZjUtYjYzMy05MjBjMzRiZDIzNTIiXSwiYXVkIjpbImh0dHBzOi8vbXlBcHAuY29tIl0sImNyZWF0ZWRBdCI6IjIwMjAtMDctMzFUMTE6NDU6MDBaIiwiZXhwIjoxNTk5NDk5MDczLCJpYXQiOjE1OTk0OTg3NzMsImlzUm9vdCI6ZmFsc2UsImlzcyI6Im15QXBwIiwidXNlcklkIjoiNWE3YzVjZGQtMzkwOS00NTZiLTlkZDItNmJhODRiZmVlYjI1IiwidXNlck5hbWUiOiJKb2huRG9lIn0.KH4YSODoTxuNLPYCyz0lmoVDHYJpvL8k6fccFugqs-6VcpctXeR4OYyWOZJDi294r6njCqRP15eqYpwrrzKKrQ" 
-}

```

Tip: you can inspect the above token in the [JWT debugger](https://jwt.io)

`sign` is a pure function, we only need `Monad` for the `currentTime` used to construct the payload.

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

While the structure of the JWT can be inferred when signing - this obviously is not the case when decoding. `decodeByteString` can't possibly know what you are going to extract from the token, so you need to give it the expected type. It can simply be _type-alias_ like in the example above. Based on this, the correct decoder is dervied. If something goes wrong an exception will be thrown, which you can catch and inspect. 

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

JWT validation is a monoid. You can append additional validations based on public and private claims, for example `checkIssuer "myApp" <> checkClaim (== True) #isRoot`. You will certainly like the fact that private claims' types are fullly known, so you can operate on type-safe Haskell values (`checkClaim ( > 0) #isRoot` will not compile). The `mempty` validation (the default validation) checks (according to [the rules in the RFC](https://tools.ietf.org/html/rfc7519#section-4.1) ) whether:
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

## Supported types

The following types are currently supported:
  * ByteString
  * String
  * Text
  * Libjwt.ASCII (for marking strings as ASCII only)
  * Libjwt.JsonByteString (for working with pure JSON)
  * Bool
  * Libjwt.NumericDate (POSIX timestamps)
  * Libjwt.Flag (for simple sum types)
  * Int
  * UUID
  * UTCTime, ZonedTime, LocalTime, Day
  * Maybes of the above types
  * lists of the above types and lists of tuples created from them
  * NonEmpty lists of the above types
  
### Flags

Flags provide a way to automatically encode and decode simple sum types.

```haskell
data Scope = Login | Extended | UserRead | UserWrite | AccountRead | AccountWrite
  deriving stock (Show, Eq, Generic)

instance AFlag Scope
```

Now, you can use `Flag Scope` in JWT claims, e.g.

```haskell
mkPayload' UserClaims {..} = jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  ( #user_name ->> userName
  , #is_root ->> isRoot
  , #user_id ->> userId
  , #created ->> createdAt
  , #accounts ->> accounts
  , #scope ->> Flag Login
  )
```

## Benchmarks

Full result sets (graphical HTML reports) are available [here](https://github.com/marcin-rzeznicki/libjwt-typed/tree/master/bench/results). 

Code can be found [here](https://github.com/marcin-rzeznicki/libjwt-typed/tree/master/bench). Benchmarking is undoubtedly hard - if you think something can be improved, please make a PR.

The Benchmarks compare `libjwt-typed` to `jose` in different hopefully real-world use cases. All the results below were obtained on a 6-Core Intel Core i7-9750H; 32 GB RAM; GHC 8.10.1 (compiled with -O2; RTS options: -N -ki2k -A512m -n32m); libjwt built with GnuTLS using GCC 10.2.0

### Signing

Measuring going from data to a fully signed, ready to send over-the-wire token

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

| what  |          libjwt          |         jose         | speedup |
| :---: | :----------------------: | :------------------: | :-----: |
| mean  | **9.05 μs**   (± 278 ns) | 166 μs   (± 5.74 μs) |   18x   |

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

| what  |          libjwt           |         jose         | speedup |
| :---: | :-----------------------: | :------------------: | :-----: |
| mean  | **35.4 μs**   (± 89.9 ns) | 525 μs   (± 9.94 μs) |   14x   |


When signing using elliptic-curve cryptography: `ECDSA256` 

|      what      |          libjwt          |         jose          | speedup |
| :------------: | :----------------------: | :-------------------: | :-----: |
| mean (simple)  | **77.3 μs**   (± 833 ns) | 1.18 ms   (± 21.6 μs) |   15x   |
| mean (complex) | **112 μs**   (± 1.17 μs) | 1.54 ms   (± 22.0 μs) |   13x   |

and `ECDSA512`

|      what      |          libjwt          |         jose          | speedup |
| :------------: | :----------------------: | :-------------------: | :-----: |
| mean (simple)  | **270 μs**   (± 4.74 μs) | 3.94 ms   (± 40.7 μs) |   14x   |
| mean (complex) | **305 μs**   (± 4.19 μs) | 4.31 ms   (± 55.5 μs) |   14x   |

And finally using the `RSA (RSASSA-PKCS1-v1_5 using SHA-512)`

|      what      |        libjwt         |           jose            | speedup |
| :------------: | :-------------------: | :-----------------------: | :-----: |
| mean (simple)  | 1.40 ms   (± 13.2 μs) | **1.03 ms**   (± 11.9 μs) |  0.7x   |
| mean (complex) | 1.44 ms   (± 15.0 μs) | **1.37 ms**   (± 15.8 μs) |  0.9x   |

This is the only time `jose` is faster (congrats!). `libjwt-typed` is slower probably because it doesn't store private key parameters. This is something thaht needs to be improved.

### Decoding

Here going from a `ByteString` token back to the data is measured. When I say "to the data" I mean user-types, not `aeson` values. This is where `libjwt-typed` has considerable leverage as it doesn't use any intermediate form, but I think it is fair as users will eventually have to parse data anyway.

Using `HMAC512`

|      what      |          libjwt          |         jose         | speedup |
| :------------: | :----------------------: | :------------------: | :-----: |
| mean (simple)  | **9.29 μs**   (± 143 ns) | 128 μs   (± 3.40 μs) |   13x   |
| mean (complex) | **60.0 μs**   (± 691 ns) | 390 μs   (± 6.12 μs) |   6x    |

Using `ECDSA256`

|      what      |          libjwt          |         jose          | speedup |
| :------------: | :----------------------: | :-------------------: | :-----: |
| mean (simple)  | **189 μs**   (± 1.49 μs) | 1.26 ms   (± 14.4 μs) |   6x    |
| mean (complex) | **244 μs**   (± 3.14 μs) | 1.54 ms   (± 15.4 μs) |   6x    |

Using `ECDSA512`

|      what      |          libjwt          |         jose          | speedup |
| :------------: | :----------------------: | :-------------------: | :-----: |
| mean (simple)  | **749 μs**   (± 8.66 μs) | 4.45 ms   (± 75.4 μs) |   5x    |
| mean (complex) | **804 μs**   (± 9.67 μs) | 4.71 ms   (± 53.8 μs) |   5x    |

And finally `RSA`

|      what      |          libjwt          |         jose         | speedup |
| :------------: | :----------------------: | :------------------: | :-----: |
| mean (simple)  | **39.4 μs**   (± 618 ns) | 138 μs   (± 3.23 μs) |   3x    |
| mean (complex) | **93.5 μs**   (± 777 ns) | 399 μs   (± 6.33 μs) |   4x    |

## Not implemented

* JWT header can only contain `alg` and `typ` (everything else is ignored). This decision is partly because of the belief that you rarely need to complicate the header, and partly because of the limiation of `libjwt` which prevents the header from being checked before decoding (this is done in one step). For this reason, things like selecting keys based on the header cannot be easily implemented.

## Idea

The idea for this lib comes from my talk ["Building a web library using super hard Haskell"](https://www.youtube.com/watch?v=icgl9FuPxKA) at the Haskell Love Conference