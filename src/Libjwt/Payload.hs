--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

-- | JWT payload structure and convenient builders.
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
import           Data.Time.Clock.POSIX

import           Data.UUID                      ( UUID )

import           Prelude                 hiding ( exp )

-- | JWT payload representation
data Payload pc ns = ClaimsSet { iss :: Iss -- ^ /iss/ (Issuer) claim
                               , sub :: Sub -- ^ /sub/ (Subject) claim
                               , aud :: Aud -- ^ /aud/ (Audience) claim
                               , exp :: Exp -- ^ /exp/ (Expiration Time) claim
                               , nbf :: Nbf -- ^ /nbf/ (Not Before) claim
                               , iat :: Iat -- ^ /iat/ (Issued At) claim
                               , jti :: Jti -- ^ /jti/ (JWT ID) claim
                               , privateClaims :: PrivateClaims pc ns -- ^ private claims
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

-- | Create a payload from the builder and the value representing private claims
--
--   For example:
-- 
-- @
-- jwtPayload
--   ('withIssuer' "myApp" <> 'withRecipient' "https://myApp.com" <> 'setTtl' 300)
--   ( #userName v'->>' "John Doe"
--   , #isRoot v'->>' False
--   , #userId v'->>' (12345 :: Int)
--   )
-- @
-- 
--  The resulting payload will be the equivalent of:
-- 
-- > {
-- >   "aud": [
-- >     "https://myApp.com"
-- >   ],
-- >   "exp": 1599499073,
-- >   "iat": 1599498773,
-- >   "isRoot": false,
-- >   "iss": "myApp",
-- >   "userId": 12345,
-- >   "userName": "JohnDoe"
-- > }
--
-- An identical payload can be constructed from the following record type:
--
-- @
-- data MyClaims = MyClaims { userName :: String
--                          , isRoot :: Bool
--                          , userId :: Int
--                          }
--   deriving stock (Eq, Show, Generic)
-- 
-- instance 'ToPrivateClaims' UserClaims
-- 
-- jwtPayload
--   ('withIssuer' "myApp" <> 'withRecipient' "https://myApp.com" <> 'setTtl' 300)
--   MyClaims { userName = "John Doe"
--            , isRoot   = False
--            , userId   = 12345
--            }
-- @
-- 
--  If you want to assign a /namespace/ to your private claims, you can do:
-- 
-- @
-- jwtPayload
--     (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
--   $ 'withNs'
--       ('Ns' @"https://myApp.com")
--       MyClaims
--         { userId    = 12345
--         , userName  = "JohnDoe"
--         , isRoot    = False
--         }
-- @
--
--  The resulting payload will be the equivalent of:
-- 
-- > {
-- >   "aud": [
-- >     "https://myApp.com"
-- >   ],
-- >   "exp": 1599499073,
-- >   "iat": 1599498773,
-- >   "https://myApp.com/isRoot": false,
-- >   "iss": "myApp",
-- >   "https://myApp.com/userId": 12345,
-- >   "https://myApp.com/userName": "JohnDoe"
-- > }
jwtPayload
  :: (MonadTime m, ToPrivateClaims a, Claims a ~ b, OutNs a ~ ns)
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
stepWithCurrentTime f = JwtBuilder . Ap $ fmap (Endo . f) askEpoch
  where
    askEpoch = do
      utcTime <- ask
      let posixTime = utcTimeToPOSIXSeconds utcTime
      let secondsSinceEpoch = nominalDiffTimeToSeconds posixTime
      pure $ NumericDate $ round secondsSinceEpoch

-- | Set /iss/ claim
withIssuer :: String -> JwtBuilder any1 any2
withIssuer issuer = step $ \p -> p { iss = Iss $ Just issuer }

-- | Set /iss/ claim
issuedBy :: String -> JwtBuilder any1 any2
issuedBy = withIssuer

-- | Set /sub/ claim
withSubject :: String -> JwtBuilder any1 any2
withSubject subject = step $ \p -> p { sub = Sub $ Just subject }

-- | Set /sub/ claim
issuedTo :: String -> JwtBuilder any1 any2
issuedTo = withSubject

-- | Append one item to /aud/ claim
withRecipient :: String -> JwtBuilder any1 any2
withRecipient recipient = step $ \p -> p { aud = Aud [recipient] <> aud p }

-- | Append one item to /aud/ claim
intendedFor :: String -> JwtBuilder any1 any2
intendedFor = withRecipient

-- | Set /aud/ claim
withAudience :: [String] -> JwtBuilder any1 any2
withAudience audience = step $ \p -> p { aud = Aud audience }

-- | Set /exp/ claim
expiresAt :: UTCTime -> JwtBuilder any1 any2
expiresAt time = step $ \p -> p { exp = Exp $ Just $ fromUTC time }

-- | Set /nbf/ claim
notBefore :: UTCTime -> JwtBuilder any1 any2
notBefore time = step $ \p -> p { nbf = Nbf $ Just $ fromUTC time }

-- | Set /nbf/ claim to 'currentTime'
notBeforeNow :: JwtBuilder any1 any2
notBeforeNow = stepWithCurrentTime $ \t p -> p { nbf = Nbf $ Just t }

-- | Set /nbf/ claim to 'currentTime' plus the argument
notUntil :: NominalDiffTime -> JwtBuilder any1 any2
notUntil s =
  stepWithCurrentTime $ \t p -> p { nbf = Nbf $ Just $ t `plusSeconds` s }

-- | Set /iat/ claim to 'currentTime'
issuedNow :: JwtBuilder any1 any2
issuedNow = stepWithCurrentTime $ \t p -> p { iat = Iat $ Just t }

-- | Set /iat/ claim to 'currentTime' and /exp/ claim to 'currentTime' plus the argument
setTtl :: NominalDiffTime -> JwtBuilder any1 any2
setTtl ttl = issuedNow <> stepWithCurrentTime
  (\t p -> p { exp = Exp $ Just $ t `plusSeconds` ttl })

-- | Set /jti/ claim
withJwtId :: UUID -> JwtBuilder any1 any2
withJwtId jwtId = step $ \p -> p { jti = Jti $ Just jwtId }
