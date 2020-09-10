--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}

module Libjwt.JwtValidation
  ( ValidationSettings(..)
  , defaultValidationSettings
  , runValidation
  , ValidationNEL
  , Valid
  , Check
  , JwtValidation
  , validation
  , checkIssuer
  , checkSubject
  , checkAge
  , checkIssuedAfter
  , checkJwtId
  , checkClaim
  , check
  , ValidationFailure(..)
  , invalid
  , valid
  )
where

import           Libjwt.NumericDate
import           Libjwt.Payload
import           Libjwt.PrivateClaims
import           Libjwt.RegisteredClaims

import           Control.Monad.Time

import           Control.Monad.Trans.Reader

import           Data.Coerce                    ( coerce )

import           Data.Either.Validation         ( Validation(..) )

import           Data.List.NonEmpty             ( NonEmpty(..) )
import           Data.Monoid                    ( Ap(..) )

import           Data.Time.Clock

import           Data.UUID                      ( UUID )

import           Prelude                 hiding ( exp )

type ValidationNEL a b = Validation (NonEmpty a) b

data ValidationEnv = Env { timestamp :: NumericDate
                         , settings :: ValidationSettings
                         }

data ValidationSettings = Settings { leeway :: NominalDiffTime
                                   , appName :: Maybe String }
  deriving stock Show

defaultValidationSettings :: ValidationSettings
defaultValidationSettings = Settings { leeway = 0, appName = Nothing }

data ValidationFailure = InvalidClaim String
                       | TokenExpired NominalDiffTime
                       | TokenNotReady NominalDiffTime
                       | WrongRecipient
                       | TokenTooOld NominalDiffTime
  deriving stock (Show, Eq)

data Valid = Valid
  deriving stock Show

instance Semigroup Valid where
  Valid <> Valid = Valid

type Check pc ns = Payload pc ns -> ValidationNEL ValidationFailure Valid

type CheckAp pc ns
  = Payload pc ns -> Ap (Validation (NonEmpty ValidationFailure)) Valid

newtype JwtValidation pc any = MkValidation { rules :: Ap (Reader ValidationEnv) (CheckAp pc any) }
  deriving newtype (Semigroup)

instance Monoid (JwtValidation any1 any2) where
  mempty = validation $ const valid

runValidation
  :: (MonadTime m)
  => ValidationSettings
  -> JwtValidation pc any
  -> Payload pc any
  -> m (ValidationNEL ValidationFailure Valid)
runValidation settings v payload =
  let MkValidation { rules } = defaultValidationRules <> v
      applyRules             = runReader (getAp rules)
  in  do
        timestamp <- now
        let env = Env { timestamp, settings }
        return $ getAp $ applyRules env payload

defaultValidationRules :: JwtValidation any1 any2
defaultValidationRules = _checkExp <> _checkNbf <> _checkAud

validation :: Check pc any -> JwtValidation pc any
validation = MkValidation . Ap . pure . coerce

using
  :: (ValidationEnv -> a) -> (a -> JwtValidation pc any) -> JwtValidation pc any
using get v = coerce (getAp . rules . v =<< asks get)

check :: String -> (a -> Bool) -> (Payload pc any -> a) -> JwtValidation pc any
check claim p get =
  validation $ (\a -> if p a then valid else invalid $ InvalidClaim claim) . get

checkIssuer :: String -> JwtValidation any1 any2
checkIssuer issuer = check "iss" (== Iss (Just issuer)) iss

checkSubject :: String -> JwtValidation any1 any2
checkSubject subject = check "sub" (== Sub (Just subject)) sub

_checkAud :: JwtValidation any1 any2
_checkAud = using (appName . settings)
  $ \ident -> validation $ rfc7519_413 ident . aud
 where
  rfc7519_413 _       (Aud []) = valid
  rfc7519_413 Nothing _        = invalid WrongRecipient
  rfc7519_413 (Just ident) (Aud rs) | ident `elem` rs = valid
                                    | otherwise       = invalid WrongRecipient

_checkExp :: JwtValidation any1 any2
_checkExp = using (leeway . settings)
  $ \skew -> using timestamp $ \t0 -> validation $ rfc7519_414 t0 skew . exp
 where
  rfc7519_414 _ _ (Exp Nothing) = valid
  rfc7519_414 t0 skew (Exp (Just t1))
    | t0 `minusSeconds` skew < t1 = valid
    | otherwise                   = invalid $ TokenExpired $ diffSeconds t0 t1

_checkNbf :: JwtValidation any1 any2
_checkNbf = using (leeway . settings)
  $ \skew -> using timestamp $ \t0 -> validation $ rfc7519_415 t0 skew . nbf
 where
  rfc7519_415 _ _ (Nbf Nothing) = valid
  rfc7519_415 t0 skew (Nbf (Just t1))
    | t0 `plusSeconds` skew >= t1 = valid
    | otherwise                   = invalid $ TokenNotReady $ diffSeconds t1 t0

checkAge :: NominalDiffTime -> JwtValidation any1 any2
checkAge maxAge = using (leeway . settings)
  $ \skew -> using timestamp $ \t0 -> validation $ ageCheck t0 skew . iat
 where
  ageCheck _ _ (Iat Nothing) = valid
  ageCheck t0 skew (Iat (Just t1))
    | age <= maxAge = valid
    | otherwise     = invalid $ TokenTooOld $ age - maxAge
    where age = diffSeconds t0 $ t1 `plusSeconds` skew

checkIssuedAfter :: UTCTime -> JwtValidation any1 any2
checkIssuedAfter time = check
  "iat"
  (\case
    Iat Nothing   -> True
    Iat (Just t1) -> t1 > fromUTC time
  )
  iat

checkJwtId :: UUID -> JwtValidation any1 any2
checkJwtId jwtId = check "jti" (== Jti (Just jwtId)) jti

checkClaim
  :: (CanGet n pc, a ~ LookupClaimType n pc)
  => (a -> Bool)
  -> ClaimName n
  -> JwtValidation pc any
checkClaim p n = check (claimNameVal n) p (getClaim n . privateClaims)

valid :: ValidationNEL ValidationFailure Valid
valid = Success Valid

invalid :: ValidationFailure -> ValidationNEL ValidationFailure Valid
invalid reason = Failure $ reason :| []

