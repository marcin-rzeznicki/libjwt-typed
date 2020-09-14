--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TypeFamilies #-}

-- | Validation of JWT claims

module Libjwt.JwtValidation
  ( ValidationSettings(..)
  , defaultValidationSettings
  , runValidation
  , ValidationNEL
  , Valid
  , Check
  , JwtValidation
  , validation
  , invalid
  , valid
  , checkIssuer
  , checkSubject
  , checkAge
  , checkIssuedAfter
  , checkJwtId
  , checkClaim
  , check
  , ValidationFailure(..)
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

-- | User-defined parameters of an validation
data ValidationSettings = Settings { leeway :: NominalDiffTime -- ^ extends the token validity period to /['nbf' - leeway, 'exp' + leeway)/ (also works for 'iat' checks such as 'checkAge')
                                   , appName :: Maybe String -- ^ used for 'aud' checks: if 'aud' claim is present, it must contain the value of this param
                                   }
  deriving stock Show

-- | 'ValidationSettings' with 'leeway' set to @0@ and 'appName' set to @Nothing@
defaultValidationSettings :: ValidationSettings
defaultValidationSettings = Settings { leeway = 0, appName = Nothing }

-- | Reasons for rejecting a JWT token
data ValidationFailure -- | User check failed 
                       = InvalidClaim String
                       -- | /exp/ check failed: the current time was after or equal to the expiration time (plus possible 'leeway')
                       | TokenExpired NominalDiffTime
                       -- | /nbf/ check failed: the current time was before the not-before time (minus possible 'leeway')
                       | TokenNotReady NominalDiffTime
                       -- | /aud/ check failed: the application processing this claim did not identify itself ('appName') with a value in the /aud/ claim
                       | WrongRecipient
                       -- | /iat/ check failed: the current time minus the time the JWT was issued (plus possible 'leeway') was greater than expected
                       | TokenTooOld NominalDiffTime
  deriving stock (Show, Eq)

data Valid = Valid
  deriving stock Show

instance Semigroup Valid where
  Valid <> Valid = Valid

type Check pc ns = Payload pc ns -> ValidationNEL ValidationFailure Valid

type CheckAp pc ns
  = Payload pc ns -> Ap (Validation (NonEmpty ValidationFailure)) Valid

-- | Construct validation from function
validation :: Check pc any -> JwtValidation pc any
validation = MkValidation . Ap . pure . coerce

-- | Validation that is always valid
valid :: ValidationNEL ValidationFailure Valid
valid = Success Valid

-- | Validation that always fails and signals @reason@
invalid
  :: ValidationFailure -- ^ reason
  -> ValidationNEL ValidationFailure Valid
invalid reason = Failure $ reason :| []

newtype JwtValidation pc any = MkValidation { rules :: Ap (Reader ValidationEnv) (CheckAp pc any) }
  deriving newtype (Semigroup)

instance Monoid (JwtValidation any1 any2) where
  mempty = validation $ const valid

-- | Runs checks against the @payload@.
--
--   The exact set of checks is: @ defaultValidationRules <> v @, where @v@ is passed to this function and @defaultValidationRules@ is:
--
--    * check /exp/ claim against the current time (minus possible 'leeway'),
--    * check /nbf/ claim against the current time (plus possible 'leeway'),
--    * check /aud/ claim against 'appName'
--
--   See the docs of 'ValidationFailure' for a list of possible errors.
runValidation
  :: (MonadTime m)
  => ValidationSettings -- ^ /leeway/ and /appName/
  -> JwtValidation pc any -- ^ v
  -> Payload pc any -- ^ payload
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

using
  :: (ValidationEnv -> a) -> (a -> JwtValidation pc any) -> JwtValidation pc any
using get v = coerce (getAp . rules . v =<< asks get)

-- | Check the property @prop@ of a payload with the predicate @p@
--
--   If @p@ is @False@, then signal @'InvalidClaim' claim@
check
  :: String -- ^ claim
  -> (a -> Bool) -- ^ p
  -> (Payload pc any -> a) -- ^ prop
  -> JwtValidation pc any
check claim p prop =
  validation
    $ (\a -> if p a then valid else invalid $ InvalidClaim claim)
    . prop

-- | Check that /iss/ is present and equal to @issuer@. If not, then signal @'InvalidClaim' "iss"@
checkIssuer
  :: String -- ^ issuer
  -> JwtValidation any1 any2
checkIssuer issuer = check "iss" (== Iss (Just issuer)) iss

-- | Check that /sub/ is present and equal to @subject@. If not, then signal @'InvalidClaim' "sub"@
checkSubject
  :: String -- ^ subject 
  -> JwtValidation any1 any2
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

-- | check that /iat/ (if present) is not further than @maxAge@ from 'currentTime' (minus possible 'leeway'). Otherwise signal 'TokenTooOld'.
checkAge
  :: NominalDiffTime -- ^ maxAge 
  -> JwtValidation any1 any2
checkAge maxAge = using (leeway . settings)
  $ \skew -> using timestamp $ \t0 -> validation $ ageCheck t0 skew . iat
 where
  ageCheck _ _ (Iat Nothing) = valid
  ageCheck t0 skew (Iat (Just t1))
    | age <= maxAge = valid
    | otherwise     = invalid $ TokenTooOld $ age - maxAge
    where age = diffSeconds t0 $ t1 `plusSeconds` skew

-- | check that /iat/ (if present) is after @time@. If false, signal @'InvalidClaim' "iat"@.
checkIssuedAfter
  :: UTCTime -- ^ time
  -> JwtValidation any1 any2
checkIssuedAfter time = check
  "iat"
  (\case
    Iat Nothing   -> True
    Iat (Just t1) -> t1 > fromUTC time
  )
  iat

-- | Check that /jti/ is present and equal to @jwtId@. If not, then signal @'InvalidClaim' "jti"@
checkJwtId
  :: UUID -- ^ jwtId
  -> JwtValidation any1 any2
checkJwtId jwtId = check "jti" (== Jti (Just jwtId)) jti

-- | Check that @p a == True@, where @a@ is a value of private claim @n@. If not, signal @'InvalidClaim' n@
--   
--   Example:
--   
-- @
-- 'checkClaim' not #is_root
-- @
checkClaim
  :: (CanGet n pc, a ~ LookupClaimType n pc)
  => (a -> Bool) -- ^ p
  -> ClaimName n -- ^ n
  -> JwtValidation pc any
checkClaim p n = check (claimNameVal n) p (getClaim n . privateClaims)



