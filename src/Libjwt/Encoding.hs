--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | JWT encoding definition
--   
--   __This module can be considered internal to the library__
--   Users should never need to implement the `Encode` typeclass or use any of the exported functions or types directly.
--   You'll only need to know of `Encode` typeclass if you want to write a function polymorphic in the type of payloads. 
--
--   If you want to extend the types supported by the library, see "Libjwt.Classes"
module Libjwt.Encoding
  ( EncodeResult
  , Encode(..)
  , ClaimEncoder(..)
  , nullEncode
  )
where

import           Libjwt.Classes
import           Libjwt.FFI.Jwt
import           Libjwt.JsonByteString
import           Libjwt.NumericDate

import           Data.ByteString                ( ByteString )
import           Data.ByteString.Builder        ( Builder
                                                , char7
                                                , string7
                                                , lazyByteString
                                                )
import           Data.ByteString.Builder.Extra  ( toLazyByteStringWith
                                                , safeStrategy
                                                )
import           Data.ByteString.Lazy           ( toStrict )

import           Data.Coerce                    ( coerce )
import           Data.Proxy                     ( Proxy(..) )

type EncodeResult = JwtIO ()

-- | Do not perform any action. It is used to encode things like empty lists or /Nothing/
nullEncode :: b -> EncodeResult
nullEncode = const $ return ()

data EncoderType = Native | Spec | Derived

type family EncoderDef a :: EncoderType where
  EncoderDef (Maybe a)      = 'Spec
  EncoderDef ByteString     = 'Native
  EncoderDef Bool           = 'Native
  EncoderDef Int            = 'Native
  EncoderDef NumericDate    = 'Native
  EncoderDef JsonByteString = 'Native
  EncoderDef String         = 'Derived
  EncoderDef [a]            = 'Spec
  EncoderDef _              = 'Derived

-- | Low-level definition of JWT claims encoding.
class ClaimEncoder t where
  -- | Given a pointer to /jwt_t/, mutate the structure it points to to encode the value as a named claim
  --   It relies on the functions exported from "Libjwt.FFI.Jwt" to perform an /impure/ effect of /encoding/
  encodeClaim :: String -> t -> JwtT -> EncodeResult

instance (EncoderDef a ~ ty, ClaimEncoder' ty a) => ClaimEncoder a where
  encodeClaim = encodeClaim' (Proxy :: Proxy ty)

class ClaimEncoder' (ty :: EncoderType) t where
  encodeClaim' :: proxy ty -> String -> t -> JwtT -> EncodeResult

instance ClaimEncoder a => ClaimEncoder' 'Spec (Maybe a) where
  encodeClaim' _ name (Just val) = encodeClaim name val
  encodeClaim' _ _    Nothing    = nullEncode

instance JsonBuilder a => ClaimEncoder' 'Spec [a] where
  encodeClaim' _ _    [] = nullEncode
  encodeClaim' _ name as = fromJson name $ jsonBuilder as

instance ClaimEncoder' 'Native ByteString where
  encodeClaim' _ = addGrant

instance ClaimEncoder' 'Native Bool where
  encodeClaim' _ = addGrantBool

instance ClaimEncoder' 'Native Int where
  encodeClaim' _ = addGrantInt

instance ClaimEncoder' 'Native NumericDate where
  encodeClaim' _ name = addGrantInt64 name . coerce
  {-# INLINE encodeClaim' #-}

fromJson :: String -> Builder -> JwtT -> JwtIO ()
fromJson name =
  addGrantsFromJson
    . toStrict
    . toLazyByteStringWith (safeStrategy 64 512) mempty
    . encodeAsObject1
 where
  encodeAsObject1 = objectBrackets . ((fieldName <> char7 ':') <>)
   where
    objectBrackets bs = char7 '{' <> bs <> char7 '}'
    fieldName = char7 '"' <> string7 name <> char7 '"'

instance ClaimEncoder' 'Native JsonByteString where
  encodeClaim' _ name = fromJson name . lazyByteString . toJson

instance (JwtRep b a, EncoderDef b ~ ty, ClaimEncoder' ty b) => ClaimEncoder' 'Derived a where
  encodeClaim' _ name = encodeClaim' (Proxy :: Proxy ty) name . rep

-- | Definition of claims encoding.
--   
--   The only use for the user is probably to write a function that is polymorphic in the payload type.
class Encode c where
  -- | Perform the encoding as /impure/ action
  encode :: c -> JwtT -> EncodeResult
