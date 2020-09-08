{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}

module Env where

import           Control.DeepSeq                ( NFData )

import           Control.Monad                  ( replicateM )
import           Control.Applicative            ( liftA2 )

import           Data.Char                      ( isPrint )
import           Data.List.NonEmpty
import qualified Data.List.NonEmpty            as NEL

import           Data.Text                      ( Text )
import qualified Data.Text                     as T

import           Data.Time.Clock                ( UTCTime )
import           Data.Time.Clock.POSIX          ( POSIXTime
                                                , getPOSIXTime
                                                , posixSecondsToUTCTime
                                                )

import           Data.UUID                      ( UUID )
import qualified Data.UUID                     as UUID
import qualified Data.UUID.V4                  as UUIDV4

import           GHC.Generics

import           Test.QuickCheck

data BenchEnv = LocalEnv { uuid :: UUID
                         , subject :: String
                         , currentTime :: POSIXTime
                         , currentTimeUtc :: UTCTime
                         , someFutureTime :: POSIXTime
                         , someFutureTimeUtc :: UTCTime
                         , shortPrintableText :: Text
                         , flipBit :: Bool
                         , accountList :: NonEmpty (UUID, Text)
                         , emailsList :: [String]
                         }
  deriving stock (Show, Generic)

instance NFData BenchEnv

localEnv :: IO BenchEnv
localEnv = do
  unixTimeNow <- getPOSIXTime
  let future = unixTimeNow + 300
  LocalEnv
    <$> UUIDV4.nextRandom
    <*> (UUID.toString <$> UUIDV4.nextRandom)
    <*> pure unixTimeNow
    <*> pure (posixSecondsToUTCTime unixTimeNow)
    <*> pure future
    <*> pure (posixSecondsToUTCTime future)
    <*> generate genShortPrintableText
    <*> generate arbitrary
    <*> exampleAccountsList
    <*> exampleEmailsList

genShortPrintableText :: Gen Text
genShortPrintableText =
  T.pack
    .          getPrintableString
    <$>        arbitrary
    `suchThat` (not . null . getPrintableString)

genShortASCIIString :: Gen ASCIIString
genShortASCIIString =
  arbitrary
    `suchThat` (\(ASCIIString ascii) -> not (null ascii) && all isPrint ascii)

exampleAccountsList :: IO (NonEmpty (UUID, Text))
exampleAccountsList = NEL.fromList
  <$> replicateM 4 (liftA2 (,) UUIDV4.nextRandom $ generate genShortASCIIText)
  where genShortASCIIText = T.pack . getASCIIString <$> genShortASCIIString

exampleEmailsList :: IO [String]
exampleEmailsList = replicateM
  2
  (generate $ (++ "@example.com") . getASCIIString <$> genShortASCIIString)

