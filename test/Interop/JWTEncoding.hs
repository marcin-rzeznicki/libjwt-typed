{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ExplicitForAll #-}
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
  describe "HS256"
    $ runTests
    $ HS256
        "MWNmYzExODA5OWFjOGM3NDNmMmM5Zjg5ZDc0YTM3M2VhMGNkMzA2MDY3ZjFhZDk5N2I3OTc5Yjdm\
        \NDg3NDBkMiAgLQo"
  xdescribe "none" $ runTests None -- JWT does not work at all with none
  describe "RS256" $ runTests $ RS256 E.testRsa2048KeyPair

runTests :: Alg -> Spec
runTests alg = sequence_ $ tests <*> [alg]

tests :: [Alg -> Spec]
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

basicTest :: Alg -> Spec
basicTest alg =
  E.specify "basic"
    $   mkTest Header { alg, typ = JWT } mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test"
          <> issuedNow
          <> notBeforeNow
          <> withJwtId E.testJTI
          )
          ()

typTest :: Alg -> Spec
typTest alg =
  E.specify "typ"
    $   mkTest Header { alg, typ = Typ $ Just "jose" } mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-typ"
          <> withJwtId E.testJTI
          )
          ()

audSingleTest :: Alg -> Spec
audSingleTest alg =
  E.specify "aud-single"
    $   mkTest Header { alg, typ = JWT } mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-aud-single"
          <> withRecipient "nobody"
          )
          ()

audListTest :: Alg -> Spec
audListTest alg =
  E.specify "aud-list"
    $   mkTest Header { alg, typ = JWT } mempty
    <$> jwtPayload
          (  withIssuer "libjwt-typed-test"
          <> withSubject "test-aud-list"
          <> withRecipient "nobody-1"
          <> withRecipient "nobody-2"
          <> withRecipient "nobody-3"
          )
          ()

privateClaimsSimpleTest :: Alg -> Spec
privateClaimsSimpleTest alg =
  E.specify "private-claims-simple"
    $   mkTest
          Header { alg, typ = JWT }
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

privateClaimsComplexTest :: Alg -> Spec
privateClaimsComplexTest alg =
  E.specify "private-claims-complex"
    $   mkTest
          Header { alg, typ = JWT }
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

privateClaimsNsTest :: Alg -> Spec
privateClaimsNsTest alg =
  E.specify "private-claims-ns"
    $   mkTest
          Header { alg, typ = JWT }
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

utfTest :: Alg -> Spec
utfTest alg =
  E.specify "utf"
    $   mkTest
          Header { alg, typ = JWT }
          (JWT.ClaimsMap $ Map.fromList
            [("name", JSON.String "孔子"), ("status", JSON.String "不患人之不己知，患不知人也")]
          )
    <$> jwtPayload
          (withIssuer "libjwt-typed-test" <> withSubject "test-utf")
          (#name ->> ("孔子" :: String), #status ->> ("不患人之不己知，患不知人也" :: T.Text))

mkTest
  :: Encode (PrivateClaims cs ns)
  => Header
  -> JWT.ClaimsMap
  -> Payload cs ns
  -> Expectation
mkTest outHeader expected payload =
  let outJwt = Jwt { header = outHeader, payload }
      token  = TE.decodeASCII $ getToken $ signJwt outJwt
  in  expectDecodable token $ \unverifiedJwt -> do
        expectHeader outHeader $ JWT.header unverifiedJwt
        expectClaimsSet payload expected $ JWT.claims unverifiedJwt
        case mkSigner $ alg outHeader of
          Nothing -> pure ()
          Just signer ->
            maybe
                (  expectationFailure
                $  "Web.JWT: Unverifiable token\n"
                ++ show token
                ++ "\nheader:\n"
                ++ show outHeader
                )
                (const $ pure ())
              $ JWT.verify signer unverifiedJwt

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

  alg' (HS256 _) = Just JWT.HS256
  alg' (RS256 _) = Just JWT.RS256
  alg' _         = Nothing

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


