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

import           Libjwt.Decoding
import           Libjwt.Encoding
import           Libjwt.FFI.Jwt
import           Libjwt.FFI.Libjwt

import           Data.ByteString                ( ByteString )

import qualified Data.CaseInsensitive          as CI

-- | @"alg"@ header parameter
data Alg = None
         | HS256
         | HS384
         | HS512
         | RS256
         | RS384
         | RS512
         | ES256
         | ES384
         | ES512
  deriving stock (Show, Eq)

instance Decode Alg where
  decode = fmap matchJwtAlg . jwtGetAlg
   where
    matchJwtAlg jwtAlg | jwtAlg == jwtAlgHs256 = HS256
                       | jwtAlg == jwtAlgHs384 = HS384
                       | jwtAlg == jwtAlgHs512 = HS512
                       | jwtAlg == jwtAlgRs256 = RS256
                       | jwtAlg == jwtAlgRs384 = RS384
                       | jwtAlg == jwtAlgRs512 = RS512
                       | jwtAlg == jwtAlgEs256 = ES256
                       | jwtAlg == jwtAlgEs384 = ES384
                       | jwtAlg == jwtAlgEs512 = ES512
                       | otherwise             = None

-- | @"typ"@ header parameter
data Typ = JWT | Typ (Maybe ByteString)
  deriving stock (Show, Eq)

instance Encode Typ where
  encode (Typ (Just s)) = addHeader "typ" s
  encode _              = nullEncode

instance Decode Typ where
  decode =
    fmap
        ( maybe (Typ Nothing)
        $ \s -> if CI.mk s == "jwt" then JWT else Typ $ Just s
        )
      . getHeader "typ"

-- | JWT header representation
data Header = Header { alg :: Alg, typ :: Typ }
  deriving stock (Show, Eq)

instance Decode Header where
  decode jwt = Header <$> decode jwt <*> decode jwt
