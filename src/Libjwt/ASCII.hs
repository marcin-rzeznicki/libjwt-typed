--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

-- | ASCII character string
module Libjwt.ASCII
  ( ASCII(..)
  )
where

-- | Represents a string consisting of only ASCII characters. 
--   JWT encoding and decoding can safely skip conversion to/from UTF-8 for these values
newtype ASCII = ASCII { getASCII :: String}
  deriving stock (Eq, Ord, Read, Show)
