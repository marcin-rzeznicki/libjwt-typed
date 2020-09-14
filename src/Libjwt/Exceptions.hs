--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ExistentialQuantification #-}

-- | Exceptions that may be thrown while decoding a token
module Libjwt.Exceptions
  ( SomeDecodeException
  , DecodeException(..)
  , MissingClaim(..)
  , AlgorithmMismatch(..)
  )
where

import           Control.Exception              ( Exception(..) )
import           Data.Typeable                  ( cast )

-- | The root of the decoding exceptions hierarchy.
--   You can use it to catch all possible exceptions that may occur while decoding a token. 
data SomeDecodeException = forall e . Exception e => SomeDecodeException e

instance Show SomeDecodeException where
  show (SomeDecodeException e) = show e

instance Exception SomeDecodeException where
  displayException (SomeDecodeException e) = displayException e

-- | Thrown when the token does not represent a decodable JWT object i.e.
-- 
--       * invalid UTF-8
--       * malformed JSON
--       * its signature cannot be verified
--
--   Basically, this token cannot be accepted for further processing because either we cannot determine its authenticity or it is garbage.
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
      \ We cannot accept this token for further processing because either we cannot determine its authenticity or it is garbage."

-- | Raised when a required claim is not present in the JWT object
newtype MissingClaim = Missing String
  deriving stock (Show)

instance Exception MissingClaim where
  toException = toException . SomeDecodeException

  fromException x = do
    SomeDecodeException a <- fromException x
    cast a

  displayException (Missing name) =
    "required claim '" ++ name ++ "' is missing"

-- | Raised when the JWT object uses a different algorithm in the header then the one we are trying to decode it with
data AlgorithmMismatch = AlgorithmMismatch
  deriving stock (Show)

instance Exception AlgorithmMismatch where
  toException = toException . SomeDecodeException

  fromException x = do
    SomeDecodeException a <- fromException x
    cast a

  displayException _ =
    "The token was signed using a different algorithm than expected"
