--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

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

newtype NumericDate = NumericDate { secondsSinceEpoch :: Int64 }
  deriving stock (Show, Eq, Ord, Bounded)

fromPOSIX :: POSIXTime -> NumericDate
fromPOSIX = NumericDate . truncate

fromUTC :: UTCTime -> NumericDate
fromUTC = fromPOSIX . utcTimeToPOSIXSeconds

toPOSIX :: NumericDate -> POSIXTime
toPOSIX (NumericDate s) = fromIntegral s

now :: (MonadTime m) => m NumericDate
now = fromUTC <$> currentTime

plusSeconds :: NumericDate -> NominalDiffTime -> NumericDate
plusSeconds d s = NumericDate $ secondsSinceEpoch d + round s

minusSeconds :: NumericDate -> NominalDiffTime -> NumericDate
minusSeconds d s = plusSeconds d (-s)

diffSeconds :: NumericDate -> NumericDate -> NominalDiffTime
diffSeconds a b = toPOSIX a - toPOSIX b
