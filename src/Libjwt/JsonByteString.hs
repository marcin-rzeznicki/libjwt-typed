--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

module Libjwt.JsonByteString
  ( JsonByteString(..)
  )
where

import qualified Data.ByteString.Lazy          as Lazy

newtype JsonByteString = JsonBs { toJson :: Lazy.ByteString }
  deriving stock (Show, Eq)



