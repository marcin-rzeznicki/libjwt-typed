--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Libjwt.Payload
  ( Payload(..)
  , withIssuer
  , issuedBy
  , withSubject
  , issuedTo
  , withRecipient
  , intendedFor
  , withAudience
  , setTtl
  , expiresAt
  , notBefore
  , notBeforeNow
  , notUntil
  , issuedNow
  , withJwtId
  , JwtBuilder
  , jwtPayload
  )
where

import           Libjwt.Encoding
import           Libjwt.Decoding
import           Libjwt.NumericDate
import           Libjwt.RegisteredClaims
import           Libjwt.PrivateClaims

import           Control.Monad.Time

import           Control.Monad.Trans.Reader

import           Data.Default

import           Data.Function                  ( (&) )
import           Data.Monoid

import           Data.Time.Clock

import           Data.UUID                      ( UUID )

import           Prelude                 hiding ( exp )

data Payload pc ns = ClaimsSet { iss :: Iss
                               , sub :: Sub
                               , aud :: Aud
                               , exp :: Exp
                               , nbf :: Nbf
                               , iat :: Iat
                               , jti :: Jti
                               , privateClaims :: PrivateClaims pc ns
                               }
deriving stock instance Show (PrivateClaims pc ns) => Show (Payload pc ns)
deriving stock instance Eq (PrivateClaims pc ns) => Eq (Payload pc ns)

instance (pc ~ Empty, ns ~ 'NoNs) => Default (Payload pc ns) where
  def = ClaimsSet { iss           = def
                  , sub           = def
                  , aud           = mempty
                  , exp           = def
                  , nbf           = def
                  , iat           = def
                  , jti           = def
                  , privateClaims = def
                  }

instance Encode (PrivateClaims pc ns) => Encode (Payload pc ns) where
  encode ClaimsSet { iss, sub, aud, exp, nbf, iat, jti, privateClaims } jwt =
    encode iss jwt
      >> encode sub           jwt
      >> encode aud           jwt
      >> encode exp           jwt
      >> encode nbf           jwt
      >> encode iat           jwt
      >> encode jti           jwt
      >> encode privateClaims jwt

instance Decode (PrivateClaims pc ns) => Decode (Payload pc ns) where
  decode jwt =
    ClaimsSet
      <$> decode jwt
      <*> decode jwt
      <*> decode jwt
      <*> decode jwt
      <*> decode jwt
      <*> decode jwt
      <*> decode jwt
      <*> decode jwt

newtype JwtBuilder any1 any2 = JwtBuilder { steps :: Ap (Reader UTCTime) (Endo (Payload any1 any2)) }
  deriving newtype (Semigroup, Monoid)

jwtPayload
  :: (MonadTime m, ToPrivateClaims a, Grants a ~ b, OutNs a ~ ns)
  => JwtBuilder b ns
  -> a
  -> m (Payload b ns)
jwtPayload builder a =
  (&) initial . appEndo . runReader (getAp $ steps builder) <$> currentTime
  where initial = def { privateClaims = toPrivateClaims a }

step :: (Payload any1 any2 -> Payload any1 any2) -> JwtBuilder any1 any2
step = JwtBuilder . Ap . pure . Endo

stepWithCurrentTime
  :: (NumericDate -> Payload any1 any2 -> Payload any1 any2)
  -> JwtBuilder any1 any2
stepWithCurrentTime f = JwtBuilder . Ap $ fmap (Endo . f) now

withIssuer :: String -> JwtBuilder any1 any2
withIssuer issuer = step $ \p -> p { iss = Iss $ Just issuer }

issuedBy :: String -> JwtBuilder any1 any2
issuedBy = withIssuer

withSubject :: String -> JwtBuilder any1 any2
withSubject subject = step $ \p -> p { sub = Sub $ Just subject }

issuedTo :: String -> JwtBuilder any1 any2
issuedTo = withSubject

withRecipient :: String -> JwtBuilder any1 any2
withRecipient recipient = step $ \p -> p { aud = Aud [recipient] <> aud p }

intendedFor :: String -> JwtBuilder any1 any2
intendedFor = withRecipient

withAudience :: [String] -> JwtBuilder any1 any2
withAudience audience = step $ \p -> p { aud = Aud audience }

expiresAt :: UTCTime -> JwtBuilder any1 any2
expiresAt time = step $ \p -> p { exp = Exp $ Just $ fromUTC time }

notBefore :: UTCTime -> JwtBuilder any1 any2
notBefore time = step $ \p -> p { nbf = Nbf $ Just $ fromUTC time }

notBeforeNow :: JwtBuilder any1 any2
notBeforeNow = stepWithCurrentTime $ \t p -> p { nbf = Nbf $ Just t }

notUntil :: NominalDiffTime -> JwtBuilder any1 any2
notUntil s =
  stepWithCurrentTime $ \t p -> p { nbf = Nbf $ Just $ t `plusSeconds` s }

issuedNow :: JwtBuilder any1 any2
issuedNow = stepWithCurrentTime $ \t p -> p { iat = Iat $ Just t }

setTtl :: NominalDiffTime -> JwtBuilder any1 any2
setTtl ttl = issuedNow <> stepWithCurrentTime
  (\t p -> p { exp = Exp $ Just $ t `plusSeconds` ttl })

withJwtId :: UUID -> JwtBuilder any1 any2
withJwtId jwtId = step $ \p -> p { jti = Jti $ Just jwtId }
