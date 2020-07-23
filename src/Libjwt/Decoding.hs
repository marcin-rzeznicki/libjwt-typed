--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Libjwt.Decoding
  ( DecodeResult(..)
  , Decode(..)
  , ClaimDecoder(..)
  , decodeClaimProxied
  , decodeClaimOrThrow
  , hoistResult
  , getOrEmpty
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
import           Data.ByteString.Lazy           ( toStrict
                                                , fromStrict
                                                )

import           Data.Coerce
import           Data.Kind                      ( Constraint )
import           Data.Maybe                     ( fromMaybe )
import           Data.Proxy

newtype DecodeResult t = Result { getOptional :: JwtIO (Maybe t) }
  deriving (Functor, Applicative, Monad, Alternative) via (MaybeT JwtIO)

hoistResult :: Maybe a -> DecodeResult a
hoistResult = Result . pure

getOrEmpty :: (Monoid a) => DecodeResult a -> JwtIO a
getOrEmpty (Result x) = fromMaybe mempty <$> x

decodeClaimProxied
  :: (ClaimDecoder t) => String -> proxy t -> JwtT -> DecodeResult t
decodeClaimProxied name _ = decodeClaim name

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

class ClaimDecoder t where
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
  decodeClaim' _ name =
    (fmap (JsonBs . fromStrict)) . Result . getGrantAsJson name
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
      . toStrict
      . toJson
  {-# INLINE decodeClaim' #-}

instance (JwtRep b a, DecoderDef b ~ ty, ClaimDecoder' ty b) => ClaimDecoder' 'Derived a where
  decodeClaim' _ name =
    (hoistResult . unRep) <=< decodeClaim' (Proxy :: Proxy ty) name

type family Decodable t :: Constraint where
  Decodable t = ClaimDecoder' (DecoderDef t) t

class Decode c where
  decode :: JwtT -> JwtIO c

