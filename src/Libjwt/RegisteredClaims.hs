--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Libjwt.RegisteredClaims
  ( Iss(..)
  , Sub(..)
  , Aud(..)
  , Exp(..)
  , Nbf(..)
  , Iat(..)
  , Jti(..)
  )
where

import           Libjwt.NumericDate
import           Libjwt.Encoding
import           Libjwt.Decoding

import           Control.Applicative            ( (<|>) )
import           Data.Coerce                    ( coerce )

import           Data.Default

import           Data.Proxy

import           Data.UUID                      ( UUID )


newtype Iss = Iss (Maybe String)
  deriving stock (Show, Eq)

newtype Sub = Sub (Maybe String)
  deriving stock (Show, Eq)

newtype Aud = Aud [String]
  deriving stock (Show, Eq)
  deriving newtype (Semigroup, Monoid)

newtype Exp = Exp (Maybe NumericDate)
  deriving stock (Show, Eq)

instance Ord Exp where
  Exp _        <= Exp Nothing  = True
  Exp Nothing  <= Exp _        = False
  Exp (Just a) <= Exp (Just b) = a <= b

newtype Nbf = Nbf (Maybe NumericDate)
  deriving stock (Show, Eq, Ord)

newtype Iat = Iat (Maybe NumericDate)
  deriving stock (Show, Eq, Ord)

newtype Jti = Jti (Maybe UUID)
  deriving stock (Show, Eq)

instance Encode Iss where
  encode (Iss iss) = encodeClaim "iss" iss

instance Decode Iss where
  decode =
    coerce . getOptional . decodeClaimProxied "iss" (Proxy :: Proxy String)

instance Encode Sub where
  encode (Sub sub) = encodeClaim "sub" sub

instance Decode Sub where
  decode =
    coerce . getOptional . decodeClaimProxied "sub" (Proxy :: Proxy String)

instance Encode Aud where
  encode (Aud aud) = encodeClaim "aud" aud

instance Decode Aud where
  decode jwt = coerce $ getOrEmpty $ tryDecodeList <|> pure <$> tryDecodeSingle
   where
    tryDecodeList   = decodeClaimProxied "aud" (Proxy :: Proxy [String]) jwt
    tryDecodeSingle = decodeClaimProxied "aud" (Proxy :: Proxy String) jwt

instance Encode Exp where
  encode (Exp exp) = encodeClaim "exp" exp

instance Decode Exp where
  decode =
    coerce . getOptional . decodeClaimProxied "exp" (Proxy :: Proxy NumericDate)

instance Encode Nbf where
  encode (Nbf nbf) = encodeClaim "nbf" nbf

instance Decode Nbf where
  decode =
    coerce . getOptional . decodeClaimProxied "nbf" (Proxy :: Proxy NumericDate)

instance Encode Iat where
  encode (Iat iat) = encodeClaim "iat" iat

instance Decode Iat where
  decode =
    coerce . getOptional . decodeClaimProxied "iat" (Proxy :: Proxy NumericDate)

instance Encode Jti where
  encode (Jti jti) = encodeClaim "jti" jti

instance Decode Jti where
  decode =
    coerce . getOptional . decodeClaimProxied "jti" (Proxy :: Proxy UUID)

instance Default Iss where
  def = Iss Nothing

instance Default Sub where
  def = Sub Nothing

instance Default Exp where
  def = Exp Nothing

instance Default Nbf where
  def = Nbf Nothing

instance Default Iat where
  def = Iat Nothing

instance Default Jti where
  def = Jti Nothing
