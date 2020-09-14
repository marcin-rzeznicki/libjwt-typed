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

-- | Represents a string which is already in JSON format. 
--
--   Can be used for cases such as integration with /aeson/
--   
-- @
-- data Account = MkAccount { account_name :: Text, account_id :: UUID }
--   deriving stock (Show, Eq, Generic)
-- 
-- instance FromJSON Account
-- instance ToJSON Account
-- 
-- instance 'JwtRep' 'JsonByteString' Account where
--   rep   = Json . encode
--   unRep = decode . toJson
-- @
newtype JsonByteString = Json { toJson :: Lazy.ByteString }
  deriving stock (Show, Eq)

jsonFromStrict :: ByteString -> JsonByteString
jsonFromStrict = Json . Lazy.fromStrict

toJsonStrict :: JsonByteString -> ByteString
toJsonStrict = Lazy.toStrict . toJson

toJsonBuilder :: JsonByteString -> Builder
toJsonBuilder = lazyByteString . toJson



