--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

module Libjwt.JsonByteString
  ( JsonByteString(..)
  , jsonFromStrict
  , toJsonStrict
  , toJsonBuilder
  )
where

import           Data.ByteString                ( ByteString )
import           Data.ByteString.Builder        ( Builder
                                                , lazyByteString
                                                )
import qualified Data.ByteString.Lazy          as Lazy

newtype JsonByteString = Json { toJson :: Lazy.ByteString }
  deriving stock (Show, Eq)

jsonFromStrict :: ByteString -> JsonByteString
jsonFromStrict = Json . Lazy.fromStrict

toJsonStrict :: JsonByteString -> ByteString
toJsonStrict = Lazy.toStrict . toJson

toJsonBuilder :: JsonByteString -> Builder
toJsonBuilder = lazyByteString . toJson



