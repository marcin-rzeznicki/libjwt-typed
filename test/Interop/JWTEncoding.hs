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

import qualified Data.Aeson                    as JSON

import qualified Data.Map.Strict               as Map

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
  , audListTest
  , privateClaimsSimpleTest
  , privateClaimsComplexTest
  , privateClaimsNsTest
  , utfTest
  ]

basicTest :: SomeAlgorithm -> Spec
basicTest sa =
  E.specify "basic"
    $   mkTest sa JWT
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test"
          <> issuedNow
          <> notBeforeNow
          <> withJwtId E.testJTI
          )
          ()
    <*> E.withEpochTime
          (\t -> mempty
            { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub = JWT.stringOrURI "test"
            , JWT.iat = JWT.numericDate t
            , JWT.nbf = JWT.numericDate t
            , JWT.jti = JWT.stringOrURI $ T.pack $ UUID.toString E.testJTI
            }
          )

typTest :: SomeAlgorithm -> Spec
typTest sa =
  E.specify "typ"
    $   mkTest sa (Typ $ Just "jose")
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-typ"
          <> withJwtId E.testJTI
          )
          ()
    <*> pure
          (mempty { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
                  , JWT.sub = JWT.stringOrURI "test-typ"
                  , JWT.jti = JWT.stringOrURI $ T.pack $ UUID.toString E.testJTI
                  }
          )


audListTest :: SomeAlgorithm -> Spec
audListTest sa =
  E.specify "aud-list"
    $   mkTest sa JWT
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-aud-list"
          <> withRecipient "nobody-1"
          <> withRecipient "nobody-2"
          <> withRecipient "nobody-3"
          )
          ()
    <*> pure
          (mempty
            { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub = JWT.stringOrURI "test-aud-list"
            , JWT.aud = fmap Right
                        .   sequence
                        $   [JWT.stringOrURI]
                        <*> ["nobody-1", "nobody-2", "nobody-3"]
            }
          )

privateClaimsSimpleTest :: SomeAlgorithm -> Spec
privateClaimsSimpleTest sa =
  E.specify "private-claims-simple"
    $   mkTest sa JWT
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-private-claims-simple"
          )
          ( #name ->> ("John Doe" :: String)
          , #userId ->> (12345 :: Int)
          , #isAdmin ->> False
          )
    <*> pure
          (mempty
            { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub = JWT.stringOrURI "test-private-claims-simple"
            , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                         [ ("name"   , JSON.String "John Doe")
                                         , ("userId" , JSON.Number 12345)
                                         , ("isAdmin", JSON.Bool False)
                                         ]
            }
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
    $   mkTest sa JWT
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-private-claims-complex"
          )
          MkClaims { name   = "John Doe"
                   , userId = 12345
                   , role   = Flag RegularUser
                   }
    <*> pure
          (mempty
            { JWT.iss = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub = JWT.stringOrURI "test-private-claims-complex"
            , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                         [ ("name"  , JSON.String "John Doe")
                                         , ("userId", JSON.Number 12345)
                                         , ("role"  , JSON.String "regularUser")
                                         ]
            }
          )

privateClaimsNsTest :: SomeAlgorithm -> Spec
privateClaimsNsTest sa =
  E.specify "private-claims-ns"
    $   mkTest sa JWT
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
    <*> E.withEpochTime
          (\t -> mempty
            { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub                = JWT.stringOrURI "test-private-claims-ns"
            , JWT.iat                = JWT.numericDate t
            , JWT.nbf                = JWT.numericDate t
            , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
              [ ("http://example.com/name"   , JSON.String "John Doe")
              , ("http://example.com/userId" , JSON.Number 12345)
              , ("http://example.com/isAdmin", JSON.Bool False)
              ]
            }
          )

utfTest :: SomeAlgorithm -> Spec
utfTest sa =
  E.specify "utf"
    $   mkTest sa JWT
    <$> jwtPayload
          (withIssuer "libjwt-typed-test" <> withSubject "test-utf")
          (#name ->> ("孔子" :: String), #status ->> ("不患人之不己知，患不知人也" :: T.Text))
    <*> pure
          (mempty
            { JWT.iss                = JWT.stringOrURI "libjwt-typed-test"
            , JWT.sub                = JWT.stringOrURI "test-utf"
            , JWT.unregisteredClaims = JWT.ClaimsMap $ Map.fromList
                                         [ ("name", JSON.String "孔子")
                                         , ( "status"
                                           , JSON.String "不患人之不己知，患不知人也"
                                           )
                                         ]
            }
          )

mkTest
  :: Encode (PrivateClaims cs ns)
  => SomeAlgorithm
  -> Typ
  -> Payload cs ns
  -> JWT.JWTClaimsSet
  -> Expectation
mkTest sa@(SomeAlgorithm a) typ payload expected =
  expectDecodable token $ \unverifiedJwt -> do
    expectHeader outHeader $ JWT.header unverifiedJwt
    JWT.claims unverifiedJwt `shouldBe` expected
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
            (const expectationOk)
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
