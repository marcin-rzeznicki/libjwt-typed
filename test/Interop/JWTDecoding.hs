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
  describe "HS256" $ runTests hmac256
  describe "none" $ runTests none
  describe "RS256" $ runTests rsa256

runTests :: SomeAlgorithm -> Spec
runTests sa = sequence_ $ tests <*> [sa]

tests :: [SomeAlgorithm -> Spec]
tests =
  [ basicTest
  , typTest
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
                          , JWT.iat = JWT.numericDate 1595386660
                          , JWT.nbf = JWT.numericDate 1595386660
                          }
  in  E.specify "basic" $ mkTest joseHeader cs sa nullClaims

typTest :: SomeAlgorithm -> Spec
typTest sa =
  let joseHeader = JWT.JOSEHeader (Just "jose") Nothing Nothing Nothing
      cs         = mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                          , JWT.sub = JWT.stringOrURI "test-typ"
                          }
  in  E.xspecify "typ" $ mkTest joseHeader cs sa nullClaims -- Web.JWT always uses JWT

richHeaderTest :: SomeAlgorithm -> Spec
richHeaderTest sa =
  let joseHeader =
          JWT.JOSEHeader (Just "JWT") (Just "test") Nothing (Just "test")
      cs = mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                  , JWT.sub = JWT.stringOrURI "test-rich-header"
                  }
  in  E.specify "rich-header" $ mkTest joseHeader cs sa nullClaims

audSingleTest :: SomeAlgorithm -> Spec
audSingleTest sa =
  let joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
      cs         = mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                          , JWT.sub = JWT.stringOrURI "test-aud-single"
                          , JWT.aud = Left <$> JWT.stringOrURI "nobody"
                          }
  in  E.specify "aud-single" $ mkTest joseHeader cs sa nullClaims

audListTest :: SomeAlgorithm -> Spec
audListTest sa =
  let joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
      cs         = mempty
        { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
        , JWT.sub = JWT.stringOrURI "test-aud-list"
        , JWT.aud = fmap Right
                    .   sequence
                    $   [JWT.stringOrURI]
                    <*> ["nobody-1", "nobody-2", "nobody-3"]
        }
  in  E.specify "aud-list" $ mkTest joseHeader cs sa nullClaims

data PreferredContact = Email | Phone
  deriving stock (Show, Eq, Generic)

instance AFlag PreferredContact

unregisteredClaimsTest :: SomeAlgorithm -> Spec
unregisteredClaimsTest sa =
  let
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "test-unregistered"
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
        [ ("name"            , JSON.String "John Doe")
        , ("userId"          , JSON.Number 12345)
        , ("isAdmin"         , JSON.Bool False)
        , ("preferredContact", JSON.String "email")
        , ("systemId"        , JSON.String $ UUID.toText E.testJTI)
        , ("createdAt"       , JSON.String "2020-07-31T11:45:00Z")
        ]
      }
  in
    E.specify "unregistered-claims" $ mkTest joseHeader cs sa $ toPrivateClaims
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
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "test-unregistered-opt"
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                   [ ("name", JSON.String "John Doe")
                                   , ("userId"          , JSON.Number 12345)
                                   , ("isAdmin"         , JSON.Bool False)
                                   , ("preferredContact", JSON.String "email")
                                   ]
      }
  in
    E.specify "unregistered-claims-options"
    $ mkTest joseHeader cs sa
    $ toPrivateClaims
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
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "test-unregistered"
      , JWT.iat                = JWT.numericDate 1595386660
      , JWT.nbf                = JWT.numericDate 1595386660
      , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
        [ ("http://example.com/name"    , JSON.String "John Doe")
        , ("http://example.com/userId"  , JSON.Number 12345)
        , ("http://example.com/isAdmin" , JSON.Bool False)
        , ("http://example.com/systemId", JSON.String $ UUID.toText E.testJTI)
        ]
      }
  in
    E.specify "unregistered-claims-ns"
    $ mkTest joseHeader cs sa
    $ toPrivateClaims
    $ withNs
        (Ns @"http://example.com")
        ( #name ->> ("John Doe" :: String)
        , #userId ->> (12345 :: Int)
        , #isAdmin ->> False
        , #systemId ->> E.testJTI
        )

utfTest :: SomeAlgorithm -> Spec
utfTest sa =
  let joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
      cs         = mempty
        { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
        , JWT.sub                = JWT.stringOrURI "test-utf"
        , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                     [ ("name"  , JSON.String "孔子")
                                     , ("status", JSON.String "不患人之不己知，患不知人也")
                                     ]
        }
  in  E.specify "utf" $ mkTest joseHeader cs sa $ toPrivateClaims
        (#name ->> ("孔子" :: String), #status ->> ("不患人之不己知，患不知人也" :: T.Text))

invalidClaimTest :: SomeAlgorithm -> Spec
invalidClaimTest sa =
  let joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
      cs         = mempty
        { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
        , JWT.sub                = JWT.stringOrURI "invalid-claim-test"
        , JWT.unregisteredClaims = JWT.ClaimsMap
                                     $ Map.singleton "not-a-number" JSON.Null
        }
      token = jwtEncode cs joseHeader sa
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
  let
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
      { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
      , JWT.sub                = JWT.stringOrURI "invalid-opt-claim-test"
      , JWT.unregisteredClaims = JWT.ClaimsMap
                                   $ Map.singleton "maybeNumber" JSON.Null
      }
  in
    E.specify "invalid-opt-claim"
    $   mkTest joseHeader cs sa
    $   toPrivateClaims
    $   #maybeNumber
    ->> (Nothing :: Maybe Int)

validTokenTest :: SomeAlgorithm -> Spec
validTokenTest sa =
  let
    t0         = 1597945008
    ttl        = 60
    t1         = t0 + 30
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
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
        (jwtEncode cs joseHeader sa)
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
    t0         = 1597945008
    ttl        = 60
    t1         = t0 + 120
    joseHeader = JWT.JOSEHeader (Just "JWT") Nothing Nothing Nothing
    cs         = mempty
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
        (jwtEncode cs joseHeader sa)
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
  -> PrivateClaims cs ns
  -> E.TestEnv Expectation
mkTest inHeader inClaims sa expected =
  let token = jwtEncode inClaims inHeader sa
  in  handle (handleDecodeException token) $ decodeTest sa token $ \jwt -> do
        expectHeader inHeader $ header jwt
        expectPayload inClaims (payload jwt) expected

decodeTest
  :: Decode (PrivateClaims pc ns)
  => SomeAlgorithm
  -> T.Text
  -> (Jwt pc ns -> Expectation)
  -> E.TestEnv Expectation
decodeTest (SomeAlgorithm a) token test =
  fmap (test . getDecoded) $ E.MkTest $ decodeByteString a $ TE.encodeUtf8 token

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
  pure
    $  expectationFailure
    $  "Web.JWT: Decoding token\n"
    ++ show token
    ++ "\n\tthrew exception:\n"
    ++ show e

expectHeader :: JWT.JOSEHeader -> Header -> Expectation
expectHeader expected got = typ got `shouldBe` typ' (JWT.typ expected)
  -- mkJWTAlgorithm (alg got) `shouldBe` JWT.alg expected

 where
  typ' Nothing      = Typ Nothing
  typ' (Just "JWT") = JWT
  typ' (Just "jwt") = JWT
  typ' (Just text ) = Typ $ Just $ TE.encodeUtf8 text

  -- mkJWTAlgorithm None  = Nothing
  -- mkJWTAlgorithm HS256 = Just JWT.HS256
  -- mkJWTAlgorithm RS256 = Just JWT.RS256
  -- mkJWTAlgorithm _     = error "Unsupported algorithm"


expectPayload
  :: (Show (PrivateClaims cs ns), Eq (PrivateClaims cs ns))
  => JWT.JWTClaimsSet
  -> Payload cs ns
  -> PrivateClaims cs ns
  -> Expectation
expectPayload expected got expectedPc = got `shouldBe` ClaimsSet
  { iss           = iss' (JWT.iss expected)
  , sub           = sub' (JWT.sub expected)
  , aud           = aud' (JWT.aud expected)
  , exp           = exp' (JWT.exp expected)
  , iat           = iat' (JWT.iat expected)
  , nbf           = nbf' (JWT.nbf expected)
  , jti           = jti' (JWT.jti expected)
  , privateClaims = expectedPc
  }
 where
  stringOrURIToString  = T.unpack . JWT.stringOrURIToText

  intDateToNumericDate = fromPOSIX . JWT.secondsSinceEpoch

  iss' mt = Iss $ stringOrURIToString <$> mt

  sub' mt = Sub $ stringOrURIToString <$> mt

  aud' Nothing           = mempty
  aud' (Just (Left  s )) = Aud [stringOrURIToString s]
  aud' (Just (Right ss)) = Aud $ map stringOrURIToString ss

  exp' md = Exp $ intDateToNumericDate <$> md

  iat' md = Iat $ intDateToNumericDate <$> md

  nbf' md = Nbf $ intDateToNumericDate <$> md

  jti' mt = Jti $ UUID.fromText . JWT.stringOrURIToText =<< mt

