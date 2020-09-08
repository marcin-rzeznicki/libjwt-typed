{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}

module Benchmarks.Data
  ( Scope(..)
  )
where

import           Web.Libjwt                     ( AFlag )

import           Data.Aeson                     ( FromJSON
                                                , ToJSON
                                                )

import           GHC.Generics

data Scope = Login | Extended | UserRead | UserWrite | AccountRead | AccountWrite
  deriving stock (Show, Eq, Generic)

instance AFlag Scope
instance ToJSON Scope
instance FromJSON Scope
