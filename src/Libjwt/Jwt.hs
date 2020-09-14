--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}

-- | JWT representation, signing and decoding.

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

-- | JSON Web Token representation
data Jwt pc ns = Jwt { header :: Header, payload :: Payload pc ns }
deriving stock instance Show (PrivateClaims pc ns) => Show (Jwt pc ns)
deriving stock instance Eq (PrivateClaims pc ns) => Eq (Jwt pc ns)

instance Encode (PrivateClaims pc ns) => Encode (Jwt pc ns) where
  encode Jwt { header, payload } jwt = encode payload jwt >> encode header jwt

-- | base64url-encoded value of type @t@
newtype Encoded t = MkEncoded { getToken :: ByteString -- ^ octets of the UTF-8 representation
                              }
  deriving stock (Show, Eq)

-- | Computes the encoded JWT value with the JWS Signature in the manner defined for the algorithm @alg@ .
--   'typ' of the JWT 'Header' is set to "JWT"
--
--   Creates the serialized ouput, that is: 
--   @
--   BASE64URL(UTF8(JWT Header)) || . || BASE64URL(JWT Payload) || . || BASE64URL(JWT Signature)
--   @
sign
  :: Encode (PrivateClaims pc ns) => Alg -> Payload pc ns -> Encoded (Jwt pc ns)
sign alg payload =
  signJwt $ Jwt { header = Header { alg, typ = JWT }, payload }

-- | Computes the encoded JWT value with the JWS Signature in the manner defined for the algorithm 'alg' present in the JWT's 'header' .
--
--   Creates the serialized ouput, that is: 
--   @
--   BASE64URL(UTF8(JWT Header)) || . || BASE64URL(JWT Payload) || . || BASE64URL(JWT Signature)
--   @
signJwt :: Encode (PrivateClaims pc ns) => Jwt pc ns -> Encoded (Jwt pc ns)
signJwt it = MkEncoded $ unsafePerformJwtIO signTokenJwtIo
 where
  signTokenJwtIo = do
    jwt <- mkJwtT
    encode it jwt
    jwtEncode jwt

{-# NOINLINE signJwt #-}

-- | Decoded value of type @t@
newtype Decoded t = MkDecoded { getDecoded :: t }
  deriving stock (Show, Eq)

-- | See 'decodeByteString'
decodeString
  :: (MonadThrow m, Decode (PrivateClaims pc ns))
  => Alg
  -> String
  -> m (Decoded (Jwt pc ns))
decodeString alg = decodeByteString alg . C8.pack

-- | Parses the base64url-encoded representation to extract the serialized values for the components of the JWT.
--   Verifies that:
--   
--       (1) @token@ is a valid UTF-8 encoded representation of a completely valid JSON object,
--       (1) input JWT signature matches,
--       (1) the correct algorithm was used,
--       (1) all required fields are present.
--
--   If steps 1-2 are unuccessful, 'DecodeException' will be thrown.
--   If step 3 fails, 'AlgorithmMismatch' will be thrown.
--   If the last step fails, 'Libjwt.Exceptions.MissingClaim' will be thrown.
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

-- | Successfully validated value of type @t@
newtype Validated t = MkValid { getValid :: t }
 deriving stock (Show, Eq)

-- | Accepts or rejects successfully decoded JWT value.
--   In addition to the default rules mandated by the RFC, the application can add its own rules.
--
--   The default rules are:
--
--       * check 'exp' claim to see if the current time is before the expiration time,
--       * check 'nbf' claim to see if the current time is after or equal the not-before time,
--       * check 'aud' claim if the application identifies itself with a value in the 'aud' list (if present)
--
--   You may allow a little 'leeway' when checking time-based claims.
--
--   'aud' claim is checked against 'appName'.
validateJwt
  :: MonadTime m
  => ValidationSettings -- ^ 'leeway' and 'appName'
  -> JwtValidation pc ns -- ^ additional validation rules
  -> Decoded (Jwt pc ns) -- ^ decoded token
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
validateJwt settings v (MkDecoded jwt) =
  fmap (MkValid jwt <$) $ runValidation settings v $ payload jwt

-- | See 'jwtFromByteString'
jwtFromString
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m)
  => ValidationSettings
  -> JwtValidation pc ns
  -> Alg
  -> String
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromString settings v alg = validateJwt settings v <=< decodeString alg

-- | @jwtFromByteString = 'validateJwt' settings v <=< 'decodeByteString' alg@
--
--   In other words, it:
-- 
--   Parses the base64url-encoded representation to extract the serialized values for the components of the JWT.
--   Verifies that:
--   
--       (1) @token@ is a valid UTF-8 encoded representation of a completely valid JSON object,
--       (1) input JWT signature matches,
--       (1) the correct algorithm was used,
--       (1) all required fields are present.
--
--   If steps 1-2 are unuccessful, 'DecodeException' will be thrown.
--   If step 3 fails, 'AlgorithmMismatch' will be thrown.
--   If the last step fails, 'Libjwt.Exceptions.MissingClaim' will be thrown.
--   
--   Once the token has been successfully decoded, it is validated.
--
--   In addition to the default rules mandated by the RFC, the application can add its own rules.
--
--   The default rules are:
--
--       * check 'exp' claim to see if the current time is before the expiration time,
--       * check 'nbf' claim to see if the current time is after or equal the not-before time,
--       * check 'aud' claim if the application identifies itself with a value in the 'aud' list (if present)
--
--   You may allow a little 'leeway' when checking time-based claims.
--
--   'aud' claim is checked against 'appName'.
jwtFromByteString
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m)
  => ValidationSettings -- ^ 'leeway' and 'appName'
  -> JwtValidation pc ns -- ^ additional validation rules 
  -> Alg -- ^ algorithm used to verify the signature
  -> ByteString -- ^ base64url-encoded representation (a token)
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromByteString settings v alg =
  validateJwt settings v <=< decodeByteString alg

