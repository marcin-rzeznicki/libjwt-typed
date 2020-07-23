--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}

module Libjwt.Keys
  ( Secret(..)
  , RsaKeyPair(..)
  , EcKeyPair(..)
  )
where

import           Data.ByteString                ( ByteString )

import qualified Data.ByteString.UTF8          as UTF8

import           Data.String

newtype Secret = MkSecret { reveal :: ByteString }
  deriving stock (Show, Eq)

instance IsString Secret where
  fromString = MkSecret . UTF8.fromString

data RsaKeyPair = FromRsaPem { privKey :: ByteString, pubKey :: ByteString }
  deriving stock (Show, Eq)

data EcKeyPair = FromEcPem { ecPrivKey :: ByteString, ecPubKey :: ByteString }
  deriving stock (Show, Eq)
