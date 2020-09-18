{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Interop.JWTEncoding
  ( spec
  )
where

import           Web.Libjwt
import           Env                            ( expectationOk )
import qualified Env                           as E
import           Interop.JWTHelpers
import           Libjwt.NumericDate             ( toPOSIX )

import qualified Data.Aeson                    as JSON

import qualified Data.Map.Strict               as Map

import           Data.Maybe                     ( fromMaybe )

import qualified Data.Text                     as T
import qualified Data.Text.Encoding            as TE

import qualified Data.UUID                     as UUID

import           GHC.Generics

import           Prelude                 hiding ( exp )

import           Test.Hspec

import qualified Web.JWT                       as JWT


spec :: Spec
spec = do
  describe "HS256" $ runTests hmac256
  xdescribe "none" $ runTests none -- JWT does not work at all with none
  describe "RS256" $ runTests rsa256

runTests :: SomeAlgorithm -> Spec
runTests sa = sequence_ $ tests <*> [sa]

tests :: [SomeAlgorithm -> Spec]
tests =
  [ basicTest
  , typTest
  , audSingleTest
  , audListTest
  , privateClaimsSimpleTest
  , privateClaimsComplexTest
  , privateClaimsNsTest
  , utfTest
  ]

basicTest :: SomeAlgorithm -> Spec
basicTest sa =
  E.specify "basic"
    $   mkTest sa JWT mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test"
          <> issuedNow
          <> notBeforeNow
          <> withJwtId E.testJTI
          )
          ()

typTest :: SomeAlgorithm -> Spec
typTest sa =
  E.specify "typ"
    $   mkTest sa (Typ $ Just "jose") mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-typ"
          <> withJwtId E.testJTI
          )
          ()

audSingleTest :: SomeAlgorithm -> Spec
audSingleTest sa =
  E.specify "aud-single"
    $   mkTest sa JWT mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-aud-single"
          <> withRecipient "nobody"
          )
          ()

audListTest :: SomeAlgorithm -> Spec
audListTest sa =
  E.specify "aud-list"
    $   mkTest sa JWT mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-aud-list"
          <> withRecipient "nobody-1"
          <> withRecipient "nobody-2"
          <> withRecipient "nobody-3"
          )
          ()

privateClaimsSimpleTest :: SomeAlgorithm -> Spec
privateClaimsSimpleTest sa =
  E.specify "private-claims-simple"
    $   mkTest
          sa
          JWT
          (JWT.ClaimsMap $ Map.fromList
            [ ("name"   , JSON.String "John Doe")
            , ("userId" , JSON.Number 12345)
            , ("isAdmin", JSON.Bool False)
            ]
          )
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-private-claims-simple"
          )
          ( #name ->> ("John Doe" :: String)
          , #userId ->> (12345 :: Int)
          , #isAdmin ->> False
          )

data UserRole = Admin | RegularUser
  deriving stock (Show, Eq, Generic)

instance AFlag UserRole

data ClaimObj = MkClaims { name :: String, userId :: Int, role :: Flag UserRole }
  deriving stock Generic

instance ToPrivateClaims ClaimObj
instance FromPrivateClaims ClaimObj

privateClaimsComplexTest :: SomeAlgorithm -> Spec
privateClaimsComplexTest sa =
  E.specify "private-claims-complex"
    $   mkTest
          sa
          JWT
          (JWT.ClaimsMap $ Map.fromList
            [ ("name"  , JSON.String "John Doe")
            , ("userId", JSON.Number 12345)
            , ("role"  , JSON.String "regularUser")
            ]
          )
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-private-claims-complex"
          )
          MkClaims { name   = "John Doe"
                   , userId = 12345
                   , role   = Flag RegularUser
                   }

privateClaimsNsTest :: SomeAlgorithm -> Spec
privateClaimsNsTest sa =
  E.specify "private-claims-ns"
    $   mkTest
          sa
          JWT
          (JWT.ClaimsMap $ Map.fromList
            [ ("http://example.com/name"   , JSON.String "John Doe")
            , ("http://example.com/userId" , JSON.Number 12345)
            , ("http://example.com/isAdmin", JSON.Bool False)
            ]
          )
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-private-claims-ns"
          <> issuedNow
          <> notBeforeNow
          )
          (withNs
            (Ns @"http://example.com")
            ( #name ->> ("John Doe" :: String)
            , #userId ->> (12345 :: Int)
            , #isAdmin ->> False
            )
          )

utfTest :: SomeAlgorithm -> Spec
utfTest sa =
  E.specify "utf"
    $   mkTest
          sa
          JWT
          (JWT.ClaimsMap $ Map.fromList
            [("name", JSON.String "孔子"), ("status", JSON.String "不患人之不己知，患不知人也")]
          )
    <$> jwtPayload
          (withIssuer "libjwt-typed-test" <> withSubject "test-utf")
          (#name ->> ("孔子" :: String), #status ->> ("不患人之不己知，患不知人也" :: T.Text))

mkTest
  :: Encode (PrivateClaims cs ns)
  => SomeAlgorithm
  -> Typ
  -> JWT.ClaimsMap
  -> Payload cs ns
  -> Expectation
mkTest sa@(SomeAlgorithm a) typ expected payload =
  expectDecodable token $ \unverifiedJwt -> do
    expectHeader outHeader $ JWT.header unverifiedJwt
    expectClaimsSet payload expected $ JWT.claims unverifiedJwt
    case mkSigner sa of
      Nothing -> expectationOk
      Just signer ->
        maybe
            (  expectationFailure
            $  "Web.JWT: Unverifiable token\n"
            ++ show token
            ++ "\nheader:\n"
            ++ show outHeader
            )
            (const $ expectationOk)
          $ JWT.verify signer unverifiedJwt
 where
  outHeader = Header { alg = toHeaderAlg a, typ }
  token     = TE.decodeASCII $ getToken $ sign' typ a payload

expectDecodable
  :: T.Text -> (JWT.JWT JWT.UnverifiedJWT -> Expectation) -> Expectation
expectDecodable outToken testCase =
  maybe (expectationFailure $ "Web.JWT: Undecodable token\n" ++ show outToken)
        testCase
    $ JWT.decode outToken

expectHeader :: Header -> JWT.JOSEHeader -> Expectation
expectHeader expected got =
  got
    `shouldBe` JWT.JOSEHeader (typ' $ typ expected)
                              Nothing
                              (alg' $ alg expected)
                              Nothing
 where
  typ' JWT       = Just "JWT"
  typ' (Typ mbs) = TE.decodeUtf8 <$> mbs

  alg' HS256 = Just JWT.HS256
  alg' RS256 = Just JWT.RS256
  alg' _     = Nothing

expectClaimsSet
  :: Payload cs ns -> JWT.ClaimsMap -> JWT.JWTClaimsSet -> Expectation
expectClaimsSet expected expectedUnreg got =
  got
    `shouldBe` JWT.JWTClaimsSet (iss' $ iss expected)
                                (sub' $ sub expected)
                                (aud' $ aud expected)
                                (exp' $ exp expected)
                                (nbf' $ nbf expected)
                                (iat' $ iat expected)
                                (jti' $ jti expected)
                                expectedUnreg
 where
  stringToStringOrURI s =
    fromMaybe (error $ "JWT.stringOrURI on " ++ show s)
      $ JWT.stringOrURI
      $ T.pack s

  numericDateToIntDate d =
    fromMaybe (error $ "JWT.numericDate on " ++ show d)
      $ JWT.numericDate
      $ toPOSIX d

  iss' (Iss ms) = stringToStringOrURI <$> ms

  sub' (Sub ms) = stringToStringOrURI <$> ms

  aud' (Aud []) = Nothing
  aud' (Aud xs) = Just $ Right $ map stringToStringOrURI xs

  exp' (Exp mnd) = numericDateToIntDate <$> mnd

  nbf' (Nbf mnd) = numericDateToIntDate <$> mnd

  iat' (Iat mnd) = numericDateToIntDate <$> mnd

  jti' (Jti muid) = stringToStringOrURI . UUID.toString <$> muid

