module Main
  ( main
  , onlyProperties
  )
where

import           Interop.JWTDecoding           as JWTDecodingInterop
import           Interop.JWTEncoding           as JWTEncodingInterop
import           Properties                    as Props

import           Test.Hspec

main :: IO ()
main = hspec $ parallel $ do
  describe "Interop" $ do
    describe "JWT.encoding" JWTEncodingInterop.spec
    describe "JWT.decoding" JWTDecodingInterop.spec
  describe "Properties" Props.spec

onlyProperties :: IO ()
onlyProperties = hspec Props.spec
