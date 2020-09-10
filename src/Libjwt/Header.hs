--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

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

data Alg = None
         | HS256 Secret
         | HS384 Secret
         | HS512 Secret
         | RS256 RsaKeyPair
         | RS384 RsaKeyPair
         | RS512 RsaKeyPair
         | ES256 EcKeyPair
         | ES384 EcKeyPair
         | ES512 EcKeyPair
  deriving stock (Show, Eq)

data Typ = JWT | Typ (Maybe ByteString)
  deriving stock (Show, Eq)

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
