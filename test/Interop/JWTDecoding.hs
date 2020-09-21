{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Interop.JWTDecoding
  ( spec
  )
where

import           Web.Libjwt
import qualified Env                           as E
import           Interop.JWTHelpers

import           Control.Monad.Catch

import qualified Data.Aeson                    as JSON

import qualified Data.Either.Validation        as V

import qualified Data.List.NonEmpty            as NEL

import qualified Data.Map.Strict               as Map

import qualified Data.Text                     as T
import qualified Data.Text.Encoding            as TE

import           Data.Time.Clock                ( UTCTime )

import qualified Data.UUID                     as UUID


import           GHC.Generics

import           Prelude                 hiding ( exp )

import           Test.Hspec

import qualified Web.JWT                       as JWT


spec :: Spec
spec = do
  testAlgValidation
  describe "HS256" $ runTests hmac256
  describe "none" $ runTests none
  describe "RS256" $ runTests rsa256

testAlgValidation :: Spec
testAlgValidation =
  let maliciousSigner = JWT.HMACSecret $ getDecodingKey E.testRsa2048KeyPair
      token = TE.encodeUtf8 $ JWT.encodeSigned maliciousSigner mempty mempty
  in  E.specify "alg-validation"
        $       fmap
                  (  const
                  $  expectationFailure
                  $  "Web.JWT: unexpectedly decoded token\n"
                  ++ show token
                  )
                  (decodeByteString @ 'NoNs @Empty (RSA256 E.testRsa2048KeyPair) token
                  )
        `catch` (\AlgorithmMismatch -> E.pass)

runTests :: SomeAlgorithm -> Spec
runTests sa = sequence_ $ tests <*> [sa]

tests :: [SomeAlgorithm -> Spec]
tests =
  [ basicTest
  , richHeaderTest
  , audSingleTest
  , audListTest
  , unregisteredClaimsTest
  , unregisteredClaimsNsTest
  , unregisteredClaimsOptionsTest
  , utfTest
  , invalidClaimTest
  , invalidOptClaimTest
  , validTokenTest
  , invalidTokenTest
  ]

basicTest :: SomeAlgorithm -> Spec
basicTest sa =
  let joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing -- Web.JWT always replaces 'alg'
      cs         = mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                          , JWT.sub = JWT.stringOrURI "test"
                          , JWT.iat = JWT.numericDate E.epochTime
                          , JWT.nbf = JWT.numericDate E.epochTime
                          }
  in  E.specify "basic"
        $   mkTest joseHeader cs sa
        =<< jwtPayload
              (  withIssuer "libjwt-typed-test"
              <> withSubject "test"
              <> issuedNow
              <> notBeforeNow
              )
              ()

richHeaderTest :: SomeAlgorithm -> Spec
richHeaderTest sa =
  let joseHeader =
          JWT.JOSEHeader (Just "JWT") (Just "test") Nothing (Just "test")
      cs = mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                  , JWT.sub = JWT.stringOrURI "test-rich-header"
                  }
  in  E.specify "rich-header"
        $   mkTest joseHeader cs sa
        =<< jwtPayload
              (withIssuer "libjwt-typed-test" <> withSubject "test-rich-header")
              ()

audSingleTest :: SomeAlgorithm -> Spec
audSingleTest sa =
  let cs = mempty { JWT.sub = JWT.stringOrURI "test-aud-single"
                  , JWT.aud = Left <$> JWT.stringOrURI "nobody"
                  }
  in  E.specify "aud-single"
        $   mkTest mempty cs sa
        =<< jwtPayload
              (withSubject "test-aud-single" <> withRecipient "nobody")
              ()

audListTest :: SomeAlgorithm -> Spec
audListTest sa =
  let cs = mempty
        { JWT.sub = JWT.stringOrURI "test-aud-list"
        , JWT.aud = fmap Right
                    .   sequence
                    $   [JWT.stringOrURI]
                    <*> ["nobody-1", "nobody-2", "nobody-3"]
        }
  in  E.specify "aud-list"
        $   mkTest mempty cs sa
        =<< jwtPayload
              (  withSubject "test-aud-list"
              <> withRecipient "nobody-1"
              <> withRecipient "nobody-2"
              <> withRecipient "nobody-3"
              )
              ()

data PreferredContact = Email | Phone
  deriving stock (Show, Eq, Generic)

instance AFlag PreferredContact

unregisteredClaimsTest :: SomeAlgorithm -> Spec
unregisteredClaimsTest sa =
  let
    cs = mempty
      { JWT.sub                = JWT.stringOrURI "test-unregistered"
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
        [ ("name"            , JSON.String "John Doe")
        , ("userId"          , JSON.Number 12345)
        , ("isAdmin"         , JSON.Bool False)
        , ("preferredContact", JSON.String "email")
        , ("systemId"        , JSON.String $ UUID.toText E.testJTI)
        , ("createdAt"       , JSON.String "2020-07-31T11:45:00Z")
        ]
      }
  in  E.specify "unregistered-claims" $ mkTest mempty cs sa =<< jwtPayload
        (withSubject "test-unregistered")
        ( #name ->> ("John Doe" :: String)
        , #userId ->> (12345 :: Int)
        , #isAdmin ->> False
        , #preferredContact ->> Flag Email
        , #systemId ->> E.testJTI
        , #createdAt ->> Just (read "2020-07-31 11:45:00 UTC" :: UTCTime)
        )

unregisteredClaimsOptionsTest :: SomeAlgorithm -> Spec
unregisteredClaimsOptionsTest sa =
  let
    cs = mempty
      { JWT.sub                = JWT.stringOrURI "test-unregistered-opt"
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                   [ ("name", JSON.String "John Doe")
                                   , ("userId"          , JSON.Number 12345)
                                   , ("isAdmin"         , JSON.Bool False)
                                   , ("preferredContact", JSON.String "email")
                                   ]
      }
  in  E.specify "unregistered-claims-options"
        $   mkTest mempty cs sa
        =<< jwtPayload
              (withSubject "test-unregistered-opt")
              ( #name ->> ("John Doe" :: String)
              , #userId ->> (12345 :: Int)
              , #isAdmin ->> False
              , #preferredContact ->> Just (Flag Email)
              , #systemId ->> (Nothing :: Maybe UUID.UUID)
              , #prefs ->> ([] :: [String])
              )

unregisteredClaimsNsTest :: SomeAlgorithm -> Spec
unregisteredClaimsNsTest sa =
  let
    cs = mempty
      { JWT.sub                = JWT.stringOrURI "test-unregistered"
      , JWT.iat                = JWT.numericDate E.epochTime
      , JWT.nbf                = JWT.numericDate E.epochTime
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
        [ ("http://example.com/name"    , JSON.String "John Doe")
        , ("http://example.com/userId"  , JSON.Number 12345)
        , ("http://example.com/isAdmin" , JSON.Bool False)
        , ("http://example.com/systemId", JSON.String $ UUID.toText E.testJTI)
        ]
      }
  in  E.specify "unregistered-claims-ns" $ mkTest mempty cs sa =<< jwtPayload
        (withSubject "test-unregistered" <> issuedNow <> notBeforeNow)
        (withNs
          (Ns @"http://example.com")
          ( #name ->> ("John Doe" :: String)
          , #userId ->> (12345 :: Int)
          , #isAdmin ->> False
          , #systemId ->> E.testJTI
          )
        )

utfTest :: SomeAlgorithm -> Spec
utfTest sa =
  let cs = mempty
        { JWT.sub                = JWT.stringOrURI "test-utf"
        , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                     [ ("name"  , JSON.String "孔子")
                                     , ("status", JSON.String "不患人之不己知，患不知人也")
                                     ]
        }
  in  E.specify "utf" $ mkTest mempty cs sa =<< jwtPayload
        (withSubject "test-utf")
        (#name ->> ("孔子" :: String), #status ->> ("不患人之不己知，患不知人也" :: T.Text))

invalidClaimTest :: SomeAlgorithm -> Spec
invalidClaimTest sa =
  let cs = mempty
        { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
        , JWT.sub                = JWT.stringOrURI "invalid-claim-test"
        , JWT.unregisteredClaims = JWT.ClaimsMap
                                     $ Map.singleton "not-a-number" JSON.Null
        }
      token = jwtEncode cs mempty sa
  in  E.specify "invalid-claim"
        $       decodeTest @'["not-a-number" ->> Int] @ 'NoNs
                  sa
                  token
                  (\decoded ->
                    expectationFailure
                      $  "Web.JWT: unexpectedly decoded token\n"
                      ++ show token
                      ++ "\n to: "
                      ++ show decoded
                  )
        `catch` (\(Missing missing) -> pure $ missing `shouldBe` "not-a-number")

invalidOptClaimTest :: SomeAlgorithm -> Spec
invalidOptClaimTest sa =
  let cs = mempty
        { JWT.sub                = JWT.stringOrURI "invalid-opt-claim-test"
        , JWT.unregisteredClaims = JWT.ClaimsMap
                                     $ Map.singleton "maybeNumber" JSON.Null
        }
  in  E.specify "invalid-opt-claim" $ mkTest mempty cs sa =<< jwtPayload
        (withSubject "invalid-opt-claim-test")
        (#maybeNumber ->> (Nothing :: Maybe Int))

validTokenTest :: SomeAlgorithm -> Spec
validTokenTest sa =
  let
    t0  = 1597945008
    ttl = 60
    t1  = t0 + 30
    cs  = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "valid-token-test"
      , JWT.iat                = JWT.numericDate t0
      , JWT.exp                = JWT.numericDate $ t0 + ttl
      , JWT.nbf                = JWT.numericDate t0
      , JWT.unregisteredClaims =
        JWT.ClaimsMap $ Map.singleton "number" $ JSON.Number 30
      }
  in
    E.specifyWithTime t1 "valid-token"
    $ validationTest @'["number" ->> Int] @ 'NoNs
        sa
        (jwtEncode cs mempty sa)
        (  checkAge 3600
        <> checkIssuer "libjwt-typed-test"
        <> checkSubject "valid-token-test"
        <> checkClaim (> 0) #number
        )
    $ \result -> result `shouldSatisfy` \case
        (V.Success _) -> True
        (V.Failure _) -> False

invalidTokenTest :: SomeAlgorithm -> Spec
invalidTokenTest sa =
  let
    t0  = 1597945008
    ttl = 60
    t1  = t0 + 120
    cs  = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "invalid-token-test"
      , JWT.iat                = JWT.numericDate t0
      , JWT.exp                = JWT.numericDate $ t0 + ttl
      , JWT.nbf                = JWT.numericDate t0
      , JWT.unregisteredClaims =
        JWT.ClaimsMap $ Map.singleton "number" $ JSON.Number (-30)
      }
  in
    E.specifyWithTime t1 "invalid-token"
    $ validationTest @'["number" ->> Int] @ 'NoNs
        sa
        (jwtEncode cs mempty sa)
        (  checkAge 3600
        <> checkIssuer "libjwt-typed-test"
        <> checkSubject "valid-token-test"
        <> checkClaim (> 0) #number
        )
    $ \result -> result `shouldSatisfy` \case
        (V.Success _) -> False
        (V.Failure errors) ->
          let es = NEL.toList errors
          in  all (`elem` es)
                  [TokenExpired 60, InvalidClaim "number", InvalidClaim "sub"]

mkTest
  :: ( Show (PrivateClaims cs ns)
     , Eq (PrivateClaims cs ns)
     , Decode (PrivateClaims cs ns)
     )
  => JWT.JOSEHeader
  -> JWT.JWTClaimsSet
  -> SomeAlgorithm
  -> Payload cs ns
  -> E.TestEnv Expectation
mkTest inHeader inClaims sa expected =
  let token = jwtEncode inClaims inHeader sa
  in  handle (handleDecodeException token) $ decodeTest sa token $ \actual ->
        actual `shouldBe` expected

decodeTest
  :: Decode (PrivateClaims pc ns)
  => SomeAlgorithm
  -> T.Text
  -> (Payload pc ns -> Expectation)
  -> E.TestEnv Expectation
decodeTest (SomeAlgorithm a) token test =
  fmap (test . payload . getDecoded)
    $ E.MkTest
    $ decodeByteString a
    $ TE.encodeUtf8 token

validationTest
  :: Decode (PrivateClaims pc ns)
  => SomeAlgorithm
  -> T.Text
  -> JwtValidation pc ns
  -> (  ValidationNEL ValidationFailure (Validated (Jwt pc ns))
     -> Expectation
     )
  -> E.TestEnv Expectation
validationTest (SomeAlgorithm a) token validation test =
  fmap test
    $ E.MkTest
    $ jwtFromByteString defaultValidationSettings validation a
    $ TE.encodeUtf8 token

jwtEncode :: JWT.JWTClaimsSet -> JWT.JOSEHeader -> SomeAlgorithm -> T.Text
jwtEncode inClaims inHeader =
  maybe (JWT.encodeUnsigned inClaims inHeader)
        (\signer -> JWT.encodeSigned signer inHeader inClaims)
    . mkSigner

handleDecodeException :: T.Text -> SomeDecodeException -> E.TestEnv Expectation
handleDecodeException token e =
  E.fail
    $  "Web.JWT: Decoding token\n"
    ++ show token
    ++ "\n\tthrew exception:\n"
    ++ show e
