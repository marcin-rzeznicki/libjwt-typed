--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | JWT decoding definition
--   
--   __This module can be considered internal to the library__
--   Users should never need to implement the `Decode` typeclass or use any of the exported functions or types directly.
--   You'll only need to know of `Decode` typeclass if you want to write a function polymorphic in the type of payloads. 
--
--   If you want to extend the types supported by the library, see "Libjwt.Classes"
module Libjwt.Decoding
  ( DecodeResult(..)
  , hoistResult
  , ClaimDecoder(..)
  , Decode(..)
  , getOrEmpty
  , decodeClaimOrThrow
  , decodeClaimProxied
  , Decodable
  , JwtIO
  )
where

import           Libjwt.Classes
import           Libjwt.Exceptions              ( MissingClaim(..) )
import           Libjwt.FFI.Jwt
import           Libjwt.JsonByteString
import           Libjwt.NumericDate

import           Control.Applicative            ( Alternative )
import           Control.Monad                  ( (<=<) )

import           Control.Monad.Catch            ( throwM )

import           Control.Monad.Trans.Maybe

import           Data.ByteString                ( ByteString )

import           Data.Coerce
import           Data.Kind                      ( Constraint )
import           Data.Maybe                     ( fromMaybe )
import           Data.Proxy

newtype DecodeResult t = Result { getOptional :: JwtIO (Maybe t) }
  deriving (Functor, Applicative, Monad, Alternative) via (MaybeT JwtIO)

-- | Use pure value as 'Result'
hoistResult :: Maybe a -> DecodeResult a
hoistResult = Result . pure

-- | Action that returns 'mempty' if decoding has failed
getOrEmpty :: (Monoid a) => DecodeResult a -> JwtIO a
getOrEmpty (Result x) = fromMaybe mempty <$> x

decodeClaimProxied
  :: (ClaimDecoder t) => String -> proxy t -> JwtT -> DecodeResult t
decodeClaimProxied name _ = decodeClaim name

-- | Action that throws 'MissingClaim' if decoding has failed
decodeClaimOrThrow :: (ClaimDecoder t) => String -> proxy t -> JwtT -> JwtIO t
decodeClaimOrThrow name p =
  maybe (throwM $ Missing name) return
    <=< getOptional
    .   decodeClaimProxied name p

data DecoderType = Native | Derived

type family DecoderDef a :: DecoderType where
  DecoderDef ByteString     = 'Native
  DecoderDef Bool           = 'Native
  DecoderDef Int            = 'Native
  DecoderDef NumericDate    = 'Native
  DecoderDef JsonByteString = 'Native
  DecoderDef String         = 'Derived
  DecoderDef [a]            = 'Native
  DecoderDef _              = 'Derived

-- | Low-level definition of decoding @t@ values from JWT.
--   It relies on the functions exported from "Libjwt.FFI.Jwt" as decoding is mostly done natively.
class ClaimDecoder t where
  -- | Given a pointer to /jwt_t/, try to decode the value of type @t@
  decodeClaim :: String -> JwtT -> DecodeResult t

instance (DecoderDef a ~ ty, ClaimDecoder' ty a) => ClaimDecoder a where
  decodeClaim = decodeClaim' (Proxy :: Proxy ty)

class ClaimDecoder' (ty :: DecoderType) t where
  decodeClaim' :: proxy ty -> String -> JwtT -> DecodeResult t

instance ClaimDecoder' 'Native ByteString where
  decodeClaim' _ name = Result . getGrant name
  {-# INLINE decodeClaim' #-}

instance ClaimDecoder' 'Native Bool where
  decodeClaim' _ name = Result . getGrantBool name
  {-# INLINE decodeClaim' #-}

instance ClaimDecoder' 'Native Int where
  decodeClaim' _ name = Result . getGrantInt name
  {-# INLINE decodeClaim' #-}

instance ClaimDecoder' 'Native NumericDate where
  decodeClaim' _ name = coerce . getGrantInt64 name
  {-# INLINE decodeClaim' #-}

instance ClaimDecoder' 'Native JsonByteString where
  decodeClaim' _ name = fmap jsonFromStrict . Result . getGrantAsJson name
  {-# INLINE decodeClaim' #-}

fromJsonNative
  :: (JsonByteString -> JwtIO (Maybe a)) -> String -> JwtT -> DecodeResult a
fromJsonNative f name =
  (Result . f) <=< decodeClaim' (Proxy :: Proxy 'Native) name
{-# INLINE fromJsonNative #-}

instance JsonParser a => ClaimDecoder' 'Native [a] where
  decodeClaim' _ =
    fromJsonNative
      $ fmap (sequence =<<)
      . unsafeMapTokenizedJsonArray jsonParser
      . toJsonStrict
  {-# INLINE decodeClaim' #-}

instance (JwtRep b a, DecoderDef b ~ ty, ClaimDecoder' ty b) => ClaimDecoder' 'Derived a where
  decodeClaim' _ name =
    (hoistResult . unRep) <=< decodeClaim' (Proxy :: Proxy ty) name

type family Decodable t :: Constraint where
  Decodable t = ClaimDecoder' (DecoderDef t) t

-- | Definition of decoding @c@ values from JWT.
--   
--   The only use for the user is probably to write a function that is polymorphic in the payload type
class Decode c where
  -- | Construct an action that decodes the value of type @c@, given a pointer to /jwt_t/. The action may fail.
  decode :: JwtT -> JwtIO c

