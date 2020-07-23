--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ExistentialQuantification #-}

module Libjwt.Exceptions
  ( SomeDecodeException
  , DecodeException(..)
  , MissingClaim(..)
  , AlgorithmMismatch(..)
  )
where

import           Control.Exception              ( Exception(..) )
import           Data.Typeable                  ( cast )

data SomeDecodeException = forall e . Exception e => SomeDecodeException e

instance Show SomeDecodeException where
  show (SomeDecodeException e) = show e

instance Exception SomeDecodeException where
  displayException (SomeDecodeException e) = displayException e

newtype DecodeException = DecodeException String
  deriving stock (Show)

instance Exception DecodeException where
  toException = toException . SomeDecodeException

  fromException x = do
    SomeDecodeException a <- fromException x
    cast a

  displayException (DecodeException token) =
    "The token \n----\n"
      ++ token
      ++ "\n----\ndoes not represent a decodable JWT object.\
      \ The possible reasons include:\
      \ its signature cannot be verified;\
      \ malformed JSON;\
      \ it uses an unsupported encoding algorithm.\
      \ We cannot accept this token for further processing as we either cannot determine its authenticity or it is garbage."

newtype MissingClaim = Missing String
  deriving stock (Show)

instance Exception MissingClaim where
  toException = toException . SomeDecodeException

  fromException x = do
    SomeDecodeException a <- fromException x
    cast a

  displayException (Missing name) =
    "required claim '" ++ name ++ "' is missing"

data AlgorithmMismatch = AlgorithmMismatch
  deriving stock (Show)

instance Exception AlgorithmMismatch where
  toException = toException . SomeDecodeException

  fromException x = do
    SomeDecodeException a <- fromException x
    cast a

  displayException _ =
    "The token was signed using a different algorithm than expected"
