--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Support for simple sum types.
module Libjwt.Flag
  ( Flag(..)
  , AFlag(..)
  )
where

import           Libjwt.ASCII

import           Control.Applicative            ( (<|>) )

import           Data.Char                      ( toLower )
import           Data.Coerce                    ( coerce )

import           Data.Proxied                   ( conNameProxied )

import           Data.Proxy

import           GHC.Generics
import           GHC.TypeLits

import           Text.Casing

-- | Value that is encoded and decoded as 'AFlag'
--
--   Flags provide a way to automatically encode and decode simple sum types.
--
-- @
-- data Scope = Login | Extended | UserRead | UserWrite | AccountRead | AccountWrite
--  deriving stock (Show, Eq, Generic)
--
-- instance AFlag Scope
--
-- mkPayload = jwtPayload
--     (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
--     ( #user_name ->> "John Doe"
--     , #is_root ->> False
--     , #user_id ->> (12345 :: Int)
--     , #scope ->> Flag Login
--     )
-- @
newtype Flag a = Flag { getFlag :: a }
  deriving stock (Show, Eq)

-- | Types that can be used as /flags/ . That is, they support conversion to/from ASCII values,
--   for example, simple sum types are good candidates that can even be generically derived
--
--
-- @
-- data Scope = Login | Extended | UserRead | UserWrite | AccountRead | AccountWrite
--  deriving stock (Show, Eq, Generic)
--
-- instance AFlag Scope
-- @
--
-- >>> getFlagValue UserWrite
-- ASCII {getASCII = "userWrite"}
--
-- >>> setFlagValue (ASCII "userWrite") :: Maybe Scope
-- Just UserWrite
class AFlag a where
  getFlagValue :: a -> ASCII
  default getFlagValue :: (Generic a, GFlag (Rep a)) => a -> ASCII
  getFlagValue = ggetFlagValue . from

  setFlagValue :: ASCII -> Maybe a
  default setFlagValue :: (Generic a, GFlag (Rep a)) => ASCII -> Maybe a
  setFlagValue = fmap to . gsetFlagValue

instance AFlag a => AFlag (Flag a) where
  getFlagValue = getFlagValue . getFlag
  setFlagValue = coerce . setFlagValue @a

class GFlag f where
  ggetFlagValue :: f p -> ASCII
  gsetFlagValue :: ASCII -> Maybe (f p)

instance GFlag f => GFlag (D1 d f) where
  ggetFlagValue (M1 x) = ggetFlagValue x

  gsetFlagValue = fmap M1 . gsetFlagValue

instance (GFlag l, GFlag r) => GFlag (l :+: r) where
  ggetFlagValue (L1 x) = ggetFlagValue x
  ggetFlagValue (R1 x) = ggetFlagValue x

  gsetFlagValue string = tryL <|> tryR
   where
    tryL = L1 <$> gsetFlagValue string
    tryR = R1 <$> gsetFlagValue string

instance Constructor c => GFlag (C1 c U1) where
  ggetFlagValue _ = ASCII $ conNameToFlagValue c
    where c = conNameProxied (Proxy :: Proxy (C1 c U1 p))

  gsetFlagValue (ASCII flag) = if lower flag == lower c
    then Just (M1 U1)
    else Nothing
   where
    lower = map toLower
    c     = conNameProxied (Proxy :: Proxy (C1 c U1 p))

conNameToFlagValue :: String -> String
conNameToFlagValue = toCamel . fromHumps

instance
  ( TypeError
    ( 'Text "Only sum types with empty constructors can be flags. For instance,"
      ':$$:
      'Text "data Good = A | B | C is ok, but"
      ':$$:
      'Text "data Bad = A Int String | B | C Char is not"
    )
  ) => GFlag (C1 c (any :*: thing)) where
  ggetFlagValue = error "unreachable"
  gsetFlagValue = error "unreachable"



