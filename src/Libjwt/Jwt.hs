--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
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
  , sign'
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

import           Libjwt.Algorithms
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
import           Control.Monad                  ( (<=<)
                                                , when
                                                )

import           Data.ByteString                ( ByteString )
import qualified Data.ByteString.Char8         as C8

import           GHC.IO.Exception               ( IOErrorType(InvalidArgument) )

import           System.IO.Error                ( ioeGetErrorType )

-- | JSON Web Token representation
data Jwt pc ns = Jwt { header :: Header, payload :: Payload pc ns }
deriving stock instance Show (PrivateClaims pc ns) => Show (Jwt pc ns)
deriving stock instance Eq (PrivateClaims pc ns) => Eq (Jwt pc ns)

-- | base64url-encoded value of type @t@
newtype Encoded t = MkEncoded { getToken :: ByteString -- ^ octets of the UTF-8 representation
                              }
  deriving stock (Show, Eq)

-- | Compute the encoded JWT value with the JWS Signature in the manner defined for the @algorithm@.
--   'typ' of the JWT 'Header' is set to "JWT"
--
--   Creates the serialized ouput, that is: 
--   @
--   BASE64URL(UTF8(JWT Header)) || . || BASE64URL(JWT Payload) || . || BASE64URL(JWT Signature)
--   @
sign
  :: (Encode (PrivateClaims pc ns), SigningKey k)
  => Algorithm k -- ^ algorithm
  -> Payload pc ns -- ^ JWT payload
  -> Encoded (Jwt pc ns)
sign = sign' JWT

-- | Compute the encoded JWT value with the JWS Signature in the manner defined for the @algorithm@ .
--   'typ' of the JWT 'Header' is set to @typ@
--
--   Creates the serialized ouput, that is: 
--   @
--   BASE64URL(UTF8(JWT Header)) || . || BASE64URL(JWT Payload) || . || BASE64URL(JWT Signature)
--   @
sign'
  :: (Encode (PrivateClaims pc ns), SigningKey k)
  => Typ -- ^ typ
  -> Algorithm k -- ^ algorithm
  -> Payload pc ns -- ^ JWT payload
  -> Encoded (Jwt pc ns)
sign' ty algorithm = signJwt jwtAlg (getSigningKey key) ty
  where (jwtAlg, key) = jwtAlgWithKey algorithm

signJwt
  :: Encode (PrivateClaims pc ns)
  => JwtAlgT
  -> ByteString
  -> Typ
  -> Payload pc ns
  -> Encoded (Jwt pc ns)
signJwt jwtAlg key ty it = MkEncoded $ unsafePerformJwtIO signTokenJwtIo
 where
  signTokenJwtIo = do
    jwt <- mkJwtT
    encode it jwt
    encode ty jwt
    jwtSetAlg jwtAlg key jwt
    when (jwtAlg == jwtAlgNone && ty == JWT) $ addHeader "typ" "JWT" jwt
    jwtEncode jwt

{-# NOINLINE signJwt #-}

-- | Decoded value of type @t@
newtype Decoded t = MkDecoded { getDecoded :: t }
  deriving stock (Show, Eq)

-- | See 'decodeByteString'
decodeString
  :: (MonadThrow m, Decode (PrivateClaims pc ns), DecodingKey k)
  => Algorithm k
  -> String
  -> m (Decoded (Jwt pc ns))
decodeString algorithm = decodeByteString algorithm . C8.pack

-- | Parse the base64url-encoded representation to extract the serialized values for the components of the JWT.
--   Verify that:
--   
--       (1) @token@ is a valid UTF-8 encoded representation of a completely valid JSON object,
--       (1) input JWT signature matches the @algorithm@,
--       (1) the correct algorithm was used,
--       (1) all required fields are present.
--
--   If steps 1-2 are unuccessful, 'DecodeException' will be thrown.
--   If step 3 fails, 'AlgorithmMismatch' will be thrown.
--   If the last step fails, 'Libjwt.Exceptions.MissingClaim' will be thrown.
decodeByteString
  :: forall ns pc m k
   . (MonadThrow m, Decode (PrivateClaims pc ns), DecodingKey k)
  => Algorithm k -- ^ algorithm used to verify the signature
  -> ByteString -- ^ token
  -> m (Decoded (Jwt pc ns))
decodeByteString algorithm token = either throwM (pure . MkDecoded)
  $ unsafePerformJwtIO decodeTokenJwtIo
 where
  decodeTokenJwtIo :: JwtIO (Either SomeDecodeException (Jwt pc ns))
  decodeTokenJwtIo =
    let (jwtAlg, key) = jwtAlgWithKey algorithm
    in  try $ do
          jwt <- safeJwtDecode (getDecodingKey key) token
          unlessM ((== jwtAlg) <$> jwtGetAlg jwt) $ throwM AlgorithmMismatch
          Jwt <$> decode jwt <*> decode jwt


{-# NOINLINE decodeByteString #-}

safeJwtDecode :: ByteString -> ByteString -> JwtIO JwtT
safeJwtDecode key token =
  catchIf (\e -> ioeGetErrorType e == InvalidArgument) (jwtDecode key token)
    $ const
    $ throwM
    $ DecodeException
    $ C8.unpack token

-- | Successfully validated value of type @t@
newtype Validated t = MkValid { getValid :: t }
 deriving stock (Show, Eq)

-- | Accept or reject successfully decoded JWT value.
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
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m, DecodingKey k)
  => ValidationSettings
  -> JwtValidation pc ns
  -> Algorithm k
  -> String
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromString settings v algorithm =
  validateJwt settings v <=< decodeString algorithm

-- | @jwtFromByteString = 'validateJwt' settings v <=< 'decodeByteString' alg@
--
--   In other words, it:
-- 
--   Parses the base64url-encoded representation to extract the serialized values for the components of the JWT.
--   Verifies that:
--   
--       (1) @token@ is a valid UTF-8 encoded representation of a completely valid JSON object,
--       (1) input JWT signature matches,
--       (1) the correct @algorithm@ was used,
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
  :: (Decode (PrivateClaims pc ns), MonadTime m, MonadThrow m, DecodingKey k)
  => ValidationSettings -- ^ 'leeway' and 'appName'
  -> JwtValidation pc ns -- ^ additional validation rules 
  -> Algorithm k -- ^ algorithm used to verify the signature
  -> ByteString -- ^ base64url-encoded representation (a token)
  -> m (ValidationNEL ValidationFailure (Validated (Jwt pc ns)))
jwtFromByteString settings v algorithm =
  validateJwt settings v <=< decodeByteString algorithm

