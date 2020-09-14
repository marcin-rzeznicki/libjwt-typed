--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

-- | JWT header representation
module Libjwt.Header
  ( Alg(..)
  , Typ(..)
  , Header(..)
  )
where

import           Libjwt.Encoding
import           Libjwt.Keys
import           Libjwt.FFI.Libjwt
import           Libjwt.FFI.Jwt

import           Control.Monad                  ( when )

import           Data.ByteString                ( ByteString )
import qualified Data.ByteString               as ByteString

-- | @"alg"@ header parameter
data Alg = None
         -- | HMAC SHA-256 (secret key must be __at least 256 bits in size__)
         | HS256 Secret
         -- | HMAC SHA-384 (secret key must be __at least 384 bits in size__)
         | HS384 Secret
         -- | HMAC SHA-512 (secret key must be __at least 512 bits in size__)
         | HS512 Secret
         -- | RSASSA-PKCS1-v1_5 SHA-256 (a key of size __2048 bits or larger__ must be used with this algorithm)
         | RS256 RsaKeyPair
         -- | RSASSA-PKCS1-v1_5 SHA-384 (a key of size __2048 bits or larger__ must be used with this algorithm)
         | RS384 RsaKeyPair
         -- | RSASSA-PKCS1-v1_5 SHA-512 (a key of size __2048 bits or larger__ must be used with this algorithm)
         | RS512 RsaKeyPair
         -- | ECDSA with P-256 curve and SHA-256
         | ES256 EcKeyPair
         -- | ECDSA with P-384 curve and SHA-384
         | ES384 EcKeyPair
         -- | ECDSA with P-521 curve and SHA-512
         | ES512 EcKeyPair
  deriving stock (Show, Eq)

-- | @"typ"@ header parameter
data Typ = JWT | Typ (Maybe ByteString)
  deriving stock (Show, Eq)

-- | JWT header representation
data Header = Header { alg :: Alg, typ :: Typ }
  deriving stock (Show, Eq)

instance Encode Header where
  encode header jwt = encodeAlg (alg header) jwt >> encodeTyp (typ header) jwt
   where
    encodeAlg None           = jwtSetAlg jwtAlgNone ByteString.empty >> forceTyp
    encodeAlg (HS256 secret) = jwtSetAlg jwtAlgHs256 $ reveal secret
    encodeAlg (HS384 secret) = jwtSetAlg jwtAlgHs384 $ reveal secret
    encodeAlg (HS512 secret) = jwtSetAlg jwtAlgHs512 $ reveal secret
    encodeAlg (RS256 pem   ) = jwtSetAlg jwtAlgRs256 $ privKey pem
    encodeAlg (RS384 pem   ) = jwtSetAlg jwtAlgRs384 $ privKey pem
    encodeAlg (RS512 pem   ) = jwtSetAlg jwtAlgRs512 $ privKey pem
    encodeAlg (ES256 pem   ) = jwtSetAlg jwtAlgEs256 $ ecPrivKey pem
    encodeAlg (ES384 pem   ) = jwtSetAlg jwtAlgEs384 $ ecPrivKey pem
    encodeAlg (ES512 pem   ) = jwtSetAlg jwtAlgEs512 $ ecPrivKey pem

    encodeTyp (Typ (Just s)) = addHeader "typ" s
    encodeTyp _              = nullEncode

    forceTyp = when (typ header == JWT) . addHeader "typ" "JWT"
