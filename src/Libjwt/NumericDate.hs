--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

-- | POSIX seconds
module Libjwt.NumericDate
  ( NumericDate(..)
  , fromUTC
  , fromPOSIX
  , toPOSIX
  , now
  , plusSeconds
  , minusSeconds
  , diffSeconds
  )
where

import           Control.Monad.Time

import           Data.Int

import           Data.Time.Clock                ( NominalDiffTime
                                                , UTCTime
                                                )
import           Data.Time.Clock.POSIX          ( POSIXTime
                                                , utcTimeToPOSIXSeconds
                                                )
-- | Represents the number of seconds elapsed since 1970-01-01
--
--   Used in accordance with the RFC in 'Libjwt.RegisteredClaims.Exp', 'Libjwt.RegisteredClaims.Nbf' and 'Libjwt.RegisteredClaims.Iat' claims
newtype NumericDate = NumericDate { secondsSinceEpoch :: Int64 }
  deriving stock (Show, Eq, Ord, Bounded)

fromPOSIX :: POSIXTime -> NumericDate
fromPOSIX = NumericDate . truncate

fromUTC :: UTCTime -> NumericDate
fromUTC = fromPOSIX . utcTimeToPOSIXSeconds

toPOSIX :: NumericDate -> POSIXTime
toPOSIX (NumericDate s) = fromIntegral s

-- | Convert 'currentTime' to a number of seconds since 1970-01-01
now :: (MonadTime m) => m NumericDate
now = fromUTC <$> currentTime

-- | Add some seconds to the date
plusSeconds :: NumericDate -> NominalDiffTime -> NumericDate
plusSeconds d s = NumericDate $ secondsSinceEpoch d + round s

-- | Subtract some seconds from the date
minusSeconds :: NumericDate -> NominalDiffTime -> NumericDate
minusSeconds d s = plusSeconds d (-s)

-- | The number of seconds between two dates
diffSeconds :: NumericDate -> NumericDate -> NominalDiffTime
diffSeconds a b = toPOSIX a - toPOSIX b
