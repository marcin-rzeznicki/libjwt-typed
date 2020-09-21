--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK not-home #-}

{- |
Copyright: (c) 2020 Marcin Rzeźnicki
SPDX-License-Identifier: MPL-2.0
Maintainer: Marcin Rzeźnicki <marcin.rzeznicki@gmail.com>

The prelude for the library.

= Creating a payload

'Payload' consists of:

    * registered claims: 'Iss', 'Sub', 'Aud', 'Jti', 'Exp', 'Nbf', 'Iat'
    * private claims

Private claims can be created from:

    * "named" tuples (tuples with elements created via v'->>')
    * records that are instances of 'ToPrivateClaims'

Public claims can be created:

    * directly, by setting fields of 'Payload' record
    * via 'JwtBuilder'

Payload keeps track of names and types of private claims as a part of its type. 
In all the examples below the type is: 

@
'Payload' '["user_name" t'->>' String, "is_root" t'->>' Bool, "user_id" t'->>' Int] ''NoNs'
@

== From "named" tuples

@
{-# LANGUAGE OverloadedLabels #-}
mkPayload currentTime =
    let now = 'fromUTC' currentTime
    in  def
            { iss           = 'Iss' (Just "myApp")
            , aud           = 'Aud' ["https://myApp.com"]
            , iat           = 'Iat' (Just now)
            , exp           = 'Exp' (Just $ now `plusSeconds` 300)
            , privateClaims = 'toPrivateClaims'
                                  ( #user_name v'->>' "John Doe"
                                  , #is_root v'->>' False
                                  , #user_id v'->>' (12345 :: Int)
                                  )
            }
@

== From records

@
data UserClaims = UserClaims { user_name :: String
                             , is_root :: Bool
                             , user_id :: Int
                             }
  deriving stock (Eq, Show, Generic)

instance 'ToPrivateClaims' UserClaims

mkPayload currentTime =
    let now = 'fromUTC' currentTime
    in  def
            { iss           = Iss (Just "myApp")
            , aud           = Aud ["https://myApp.com"]
            , iat           = Iat (Just now)
            , exp           = Exp (Just $ now `plusSeconds` 300)
            , privateClaims = 'toPrivateClaims'
                              UserClaims { user_name = "John Doe"
                                         , is_root = False
                                         , user_id = 12345
                                         }
            }
@

== Using JwtBuilder

If you prefer more "fluent" style, you might want to use 'jwtPayload' function

@
mkPayload = 'jwtPayload'
   ('withIssuer' "myApp" <> 'withRecipient' "https://myApp.com" <> 'setTtl' 300)
   UserClaims { user_name = "John Doe"
              , is_root = False
              , user_id = 12345
              }
@

For the list of available "builders", please see the docs of "Libjwt.Payload" module.
This methods relies on "Control.Monad.MonadTime" to get the current time.

= Namespaces

To ensure that private do not collide with claims from other resources, it is recommended to give them globally unique names . 
This is often done through namespacing, i.e. prefixing the names with the URI of a resource you control. 
This is handled entirely at the type-level. 

As you may have noticed, 'Payload' types has a component of kind 'Namespace'. 
It tracks the namespace assigned to private claims within the payload. If you change the last example to:

@
{-# LANGUAGE DataKinds #-}

mkPayload' =
  jwtPayload
      (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
    $ 'withNs'
        ('Ns' @"https://myApp.com")
        UserClaims 
           { user_name = "John Doe"
           , is_root = False
           , user_id = 12345
           }
@

, you'll notice that the type has changed to accomodate the namespace, becoming 

@
'Payload' '["user_name" t'->>' String, "is_root" t'->>' Bool, "user_id" t'->>' Int] (''SomeNs' "https://myApp.com")
@

Consequently, in the generated token /"user_id"/ becomes /"https://myApp.com/user_id"/ etc.

= Signing

Signing is the process of transforming the 'Jwt' structure with 'Payload' and 'Header' into a token with a cryptographic signature that can be sent over-the-wire.

== Supported algorithms

To sign a token, you need to choose the algorithm. 

+------------+---------------------------------------+-------------+
|Algorithm   |  Description                          |  Key type   |
+============+=======================================+=============+
|'HMAC256'   |  HMAC with SHA-256                    |  'Secret'   |
+------------+---------------------------------------+             |
|'HMAC384'   |  HMAC with SHA-384                    |             |
+------------+---------------------------------------+             |
|'HMAC512'   |  HMAC with SHA-512                    |             |
+------------+---------------------------------------+-------------+
|'RSA256'    |  RSASSA-PKCS1-v1_5 with SHA-256       | 'RsaKeyPair'|
+------------+---------------------------------------+ 'RsaPubKey' |
|'RSA384'    |  RSASSA-PKCS1-v1_5 with SHA-384       |             |
+------------+---------------------------------------+             |
|'RSA512'    |  RSASSA-PKCS1-v1_5 with SHA-512       |             |
+------------+---------------------------------------+-------------+
|'ECDSA256'  |  ECDSA with curve P-256 and SHA-256   | 'EcKeyPair' |
+------------+---------------------------------------+ 'EcPubKey'  |
|'ECDSA384'  |  ECDSA with curve P-384 and SHA-384   |             |
+------------+---------------------------------------+             |
|'ECDSA512'  |  ECDSA with curve P-521 and SHA-512   |             |
+------------+---------------------------------------+-------------+

The complete example: 

@
{-# LANGUAGE OverloadedStrings #-}

hmac512 :: 'Algorithm' 'Secret'
hmac512 =
    'HMAC512'
        "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\\
        \\YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\\
        \\Y2IwMDZhYWY1MjY1OTQgIC0K"

token :: IO ByteString
token = fmap ('getToken' . 'sign' hmac512) $ jwtPayload
    (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
    UserClaims { user_name = "John Doe"
               , is_root = False
               , user_id = 12345
               }
@

= Decoding

Decoding is a 2-step process. /Step 1/ is to take the token, validate its signature and check its structural correctness 
(is it valid JSON, is it a valid JWT object, does it have all the claims?). If any of these tests fail,
we don't have a valid token and an exception is thrown (see 'SomeDecodeException'). In /step 2/, the decoded token is validated -
has it expired? does it have the right issuer? etc. The resulting value is of type @'ValidationNEL' 'ValidationFailure' ('Validated' MyJwtType)@

It is __important__ to only work with valid tokens (if a token is not validated, it may be addressed to someone else or may be 2 weeks old),
so the rest of your program should only accept @'Validated' MyJwt@, not @'Decoded' MyJwt@, which is the result of step 1.

@
type MyJwt
    = 'Jwt'
          '["userId" t'->>' UUID, "userName" t'->>' Text, "isRoot" t'->>' Bool, "createdAt" t'->>' UTCTime, "accounts" t'->>' NonEmpty UUID]
          ''NoNs'

decodeAndValidate :: IO ('ValidationNEL' 'ValidationFailure' ('Validated' MyJwt))
decodeAndValidate = 'jwtFromByteString' settings mempty hmac512 =<< token
  where
    settings = 'Settings' { leeway = 5, appName = Just "https://myApp.com" }
@

By default only validations mandated by the RFC are performed:

    * check /exp/ claim against the current time,
    * check /nbf/ claim against the current time,
    * check /aud/ claim against 'appName'

You can add your own validations:

@
decodeAndValidate :: IO ('ValidationNEL' 'ValidationFailure' ('Validated' MyJwt))
decodeAndValidate = 'jwtFromByteString' settings ('checkIssuer' "myApp" <> 'checkClaim' not #is_root) hmac512 =<< token
  where
    settings = 'Settings' { leeway = 5, appName = Just "https://myApp.com" }
@

If for some reason, you do not want to validate a token, but only decode it, you can use 'decodeByteString'

= Types supported in claims

Currently, these types are supported:

    * ByteString
    * String
    * Text
    * 'ASCII'
    * 'Libjwt.JsonByteString'
    * Bool
    * 'NumericDate'
    * 'Flag'
    * Int
    * UUID
    * UTCTime, ZonedTime, LocalTime, Day
    * Maybes of the above type
    * lists of the above types and lists of tuples created from them
    * NonEmpty lists of the above types
    
If you want to support a different type, check out "Libjwt.Classes".
If you want to work with aeson, check "Libjwt.JsonByteString"

-}

module Web.Libjwt
    ( module Libjwt.Jwt
    , module Libjwt.Algorithms
    , module Libjwt.Exceptions
    , module Libjwt.Header
    , module Libjwt.Keys
    , module Libjwt.Payload
    , module Libjwt.RegisteredClaims
    , module Libjwt.PrivateClaims
    , module Libjwt.JwtValidation
    , module Libjwt.NumericDate
    , module Libjwt.ASCII
    , module Libjwt.Flag
    , module Libjwt.Encoding
    , module Libjwt.Decoding
    )
where

import           Libjwt.Algorithms              ( Algorithm(..) )
import           Libjwt.ASCII                   ( ASCII(..) )
import           Libjwt.Decoding                ( Decode )
import           Libjwt.Encoding                ( Encode )
import           Libjwt.Exceptions
import           Libjwt.Flag                    ( Flag(..)
                                                , AFlag(..)
                                                )
import           Libjwt.Header
import           Libjwt.Jwt                     ( Jwt(..)
                                                , sign
                                                , sign'
                                                , Encoded
                                                , getToken
                                                , jwtFromString
                                                , jwtFromByteString
                                                , decodeString
                                                , decodeByteString
                                                , Decoded
                                                , getDecoded
                                                , validateJwt
                                                , Validated
                                                , getValid
                                                )
import           Libjwt.JwtValidation    hiding ( runValidation
                                                , Valid
                                                , Check
                                                , invalid
                                                , valid
                                                , validation
                                                )
import           Libjwt.Keys
import           Libjwt.NumericDate             ( NumericDate(..)
                                                , fromUTC
                                                , fromPOSIX
                                                , plusSeconds
                                                )
import           Libjwt.Payload
import           Libjwt.PrivateClaims
import           Libjwt.RegisteredClaims

