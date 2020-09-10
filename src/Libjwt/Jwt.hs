--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}

module Libjwt.Jwt
  ( Jwt(..)
  , Encoded
  , getToken
  , sign
  , signJwt
  , Decoded
  , getDecoded
  , decodeString
  , decodeByteString
  , Validated
  , getValid
  , validateJwt
  , jwtFromString
  , jwtFromByteString
  )
where

import           Libjwt.Encoding
import           Libjwt.Exceptions              ( SomeDecodeException
                                                , AlgorithmMismatch(..)
                                                , DecodeException(..)
                                                )
import           Libjwt.Decoding
import           Libjwt.FFI.Jwt
import           Libjwt.FFI.Libjwt
import           Libjwt.Header
import           Libjwt.JwtValidation
import           Libjwt.Keys
import           Libjwt.Payload
import           Libjwt.PrivateClaims

import           Control.Monad.Catch

import           Control.Monad.Extra            ( unlessM )

import           Control.Monad.Time
import           Control.Monad                  ( (<=<) )

import           Data.ByteString                ( ByteString )
import qualified Data.ByteString.Char8         as C8

import qualified Data.CaseInsensitive          as CI

import           GHC.IO.Exception               ( IOErrorType(InvalidArgument) )

import           System.IO.Error                ( ioeGetErrorType )


data Jwt pc ns = Jwt { header :: Header, payload :: Payload pc ns }
deriving stock instance Show (PrivateClaims pc ns) => Show (Jwt pc ns)
deriving stock instance Eq (PrivateClaims pc ns) => Eq (Jwt pc ns)

instance Encode (PrivateClaims pc ns) => Encode (Jwt pc ns) where
  encode Jwt { header, payload } jwt = encode payload jwt >> encode header jwt

newtype Encoded t = MkEncoded { getToken :: ByteString }
  deriving stock (Show, Eq)

sign
  :: Encode (PrivateClaims pc ns) => Alg -> Payload pc ns -> Encoded (Jwt pc ns)
sign alg payload =
  signJwt $ Jwt { header = Header { alg, typ = JWT }, payload }

signJwt :: Encode (PrivateClaims pc ns) => Jwt pc ns -> Encoded (Jwt pc ns)
signJwt it = MkEncoded $ unsafePerformJwtIO signTokenJwtIo
 where
  signTokenJwtIo = do
    jwt <- mkJwtT
    encode it jwt
    jwtEncode jwt

{-# NOINLINE signJwt #-}

newtype Decoded t = MkDecoded { getDecoded :: t }
  deriving stock (Show, Eq)

decodeString
  :: (MonadThrow m, Decode (PrivateClaims pc ns))
  => Alg
  -> String
  -> m (Decoded (Jwt pc ns))
decodeString alg = decodeByteString alg . C8.pack

decodeByteString
  :: forall ns pc m
   . (MonadThrow m, Decode (PrivateClaims pc ns))
  => Alg
  -> ByteString
  -> m (Decoded (Jwt pc ns))
decodeByteString alg token = either throwM (pure . MkDecoded)
  $ unsafePerformJwtIO decodeTokenJwtIo
 where
  decodeTokenJwtIo :: JwtIO (Either SomeDecodeException (Jwt pc ns))
  decodeTokenJwtIo = try $ do
    jwt <- safeJwtDecode alg token
    unlessM (matchAlg alg <$> jwtGetAlg jwt) $ throwM AlgorithmMismatch
    Jwt <$> decodeHeader jwt <*> decode jwt

  decodeHeader = fmap (Header alg) . decodeTyp

  decodeTyp =
    fmap
        ( maybe (Typ Nothing)
        $ \s -> if CI.mk s == "jwt" then JWT else Typ $ Just s
        )
      . getHeader "typ"

  matchAlg (HS256 _) = (== jwtAlgHs256)
  matchAlg (HS384 _) = (== jwtAlgHs384)
  matchAlg (HS512 _) = (== jwtAlgHs512)
  matchAlg (RS256 _) = (== jwtAlgRs256)
  matchAlg (RS384 _) = (== jwtAlgRs384)
  matchAlg (RS512 _) = (== jwtAlgRs512)
  matchAlg (ES256 _) = (== jwtAlgEs256)
  matchAlg (ES384 _) = (== jwtAlgEs384)
  matchAlg (ES512 _) = (== jwtAlgEs512)
  matchAlg None      = (== jwtAlgNone)

{-# NOINLINE decodeByteString #-}

safeJwtDecode :: Alg -> ByteString -> JwtIO JwtT
safeJwtDecode alg token =
  catchIf (\e -> ioeGetErrorType e == InvalidArgument)
          (jwtDecode (getKey alg) token)
    $ const
    $ throwM
    $ DecodeException
    $ C8.unpack token
 where
  getKey (HS256 secret) = Just $ reveal secret
  getKey (HS384 secret) = Just $ reveal secret
  getKey (HS512 secret) = Just $ reveal secret
  getKey (RS256 pem   ) = Just $ pubKey pem
  getKey (RS384 pem   ) = Just $ pubKey pem
  getKey (RS512 pem   ) = Just $ pubKey pem
  getKey (ES256 pem   ) = Just $ ecPubKey pem
  getKey (ES384 pem   ) = Just $ ecPubKey pem
  getKey (ES512 pem   ) = Just $ ecPubKey pem
  getKey None           = Nothing

newtype Validated t = MkValid { getValid :: t }
 deriving stock (Show, Eq)

validateJwt
  :: MonadTime m
  => ValidationSettings
  -> JwtValidation pc ns
  -> Decoded (Jwt pc ns)
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
validateJwt settings v (MkDecoded jwt) =
  fmap (MkValid jwt <$) $ runValidation settings v $ payload jwt

jwtFromString
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m)
  => ValidationSettings
  -> JwtValidation pc ns
  -> Alg
  -> String
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromString settings v alg = validateJwt settings v <=< decodeString alg

jwtFromByteString
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m)
  => ValidationSettings
  -> JwtValidation pc ns
  -> Alg
  -> ByteString
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromByteString settings v alg =
  validateJwt settings v <=< decodeByteString alg

