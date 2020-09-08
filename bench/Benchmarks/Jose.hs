{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Benchmarks.Jose
  ( signSimple
  , decodeSimple
  , signCustomClaims
  , decodeCustomClaims
  , signCustomClaimsWithNs
  , decodeCustomClaimsWithNs
  , signComplexClaims
  , decodeComplexClaims
  )
where

import           Benchmarks.Data
import           Env


import           Control.Lens.Operators         ( (?~)
                                                , (&)
                                                , (.~)
                                                , (^?)
                                                )
import           Control.Lens.Combinators       ( view )

import           Control.Monad.Trans.Except     ( runExceptT
                                                , except
                                                )

import           Criterion                      ( Benchmark
                                                , bench
                                                , env
                                                , nfAppIO
                                                , whnfAppIO
                                                )

import           Crypto.JOSE.JWK
import           Crypto.JWT

import           Data.Aeson                     ( Value
                                                , Result(..)
                                                , toJSON
                                                , fromJSON
                                                )

import           Data.ByteString                ( ByteString )
import           Data.ByteString.Lazy           ( toStrict
                                                , fromStrict
                                                )

import           Data.HashMap.Strict            ( HashMap
                                                , (!)
                                                )

import           Data.Text                      ( Text )
import qualified Data.Text                     as T

import           Data.Time.Clock                ( UTCTime )

import           Data.UUID                      ( UUID )
import           Data.List.NonEmpty             ( NonEmpty )


doSign :: Alg -> JWK -> ClaimsSet -> IO ByteString
doSign a k claims =
  either (fail . (show :: JWTError -> String))
         (return . toStrict . encodeCompact)
    =<< runExceptT (signClaims k (newJWSHeader ((), a)) claims)

prepareToken :: (BenchEnv -> ClaimsSet) -> Alg -> JWK -> IO ByteString
prepareToken f a k = localEnv >>= doSign a k . f

decodeJson :: (HashMap Text Value -> Result b) -> ClaimsSet -> Either JWTError b
decodeJson f claimsSet = case f (view unregisteredClaims claimsSet) of
  Success d   -> Right d
  Error   str -> Left $ JWTClaimsSetDecodeError str



baseClaimsSet :: BenchEnv -> ClaimsSet
baseClaimsSet LocalEnv {..} =
  let _subject = subject ^? stringOrUri
      _iat     = NumericDate currentTimeUtc
      _exp     = NumericDate someFutureTimeUtc
  in  emptyClaimsSet
        &  claimIss
        ?~ "benchmarks"
        &  claimSub
        .~ _subject
        &  claimAud
        ?~ Audience ["https://example.com"]
        &  claimIat
        ?~ _iat
        &  claimExp
        ?~ _exp
        &  claimNbf
        ?~ _iat

signSimple :: (Alg, JWK) -> Benchmark
signSimple (a, k) = env localEnv $ bench "simple" . nfAppIO benchmark
  where benchmark = doSign a k . baseClaimsSet

decodeSimple :: (Alg, JWK) -> Benchmark
decodeSimple (a, k) =
  env (prepareToken baseClaimsSet a k) $ bench "simple" . whnfAppIO benchmark
 where
  benchmark :: ByteString -> IO (Either JWTError ClaimsSet)
  benchmark token =
    runExceptT
      $   decodeCompact (fromStrict token)
      >>= verifyClaims (validation & issuerPredicate .~ (== "benchmarks")) k



mkCustomClaims :: BenchEnv -> ClaimsSet
mkCustomClaims e@LocalEnv {..} =
  addClaim "scope" (toJSON Login)
    $ addClaim "created"  (toJSON currentTimeUtc)
    $ addClaim "clientId" (toJSON uuid)
    $ addClaim "isRoot"   (toJSON flipBit)
    $ addClaim "userName" (toJSON shortPrintableText)
    $ baseClaimsSet e

signCustomClaims :: (Alg, JWK) -> Benchmark
signCustomClaims (a, k) =
  env localEnv $ bench "custom-claims" . nfAppIO benchmark
  where benchmark = doSign a k . mkCustomClaims

decodeCustomClaims :: (Alg, JWK) -> Benchmark
decodeCustomClaims (a, k) =
  env (prepareToken mkCustomClaims a k)
    $ bench "custom-claims"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (Either JWTError (Text, Bool, UUID, UTCTime, Scope))
  benchmark token =
    runExceptT
      $   decodeCompact (fromStrict token)
      >>= verifyClaims (validation & issuerPredicate .~ (== "benchmarks")) k
      >>= except
      .   decodeJson decodeData

  decodeData claims =
    (,,,,)
      <$> fromJSON (claims ! "userName")
      <*> fromJSON (claims ! "isRoot")
      <*> fromJSON (claims ! "clientId")
      <*> fromJSON (claims ! "created")
      <*> fromJSON (claims ! "scope")



mkCustomClaimsWithNs :: Text -> BenchEnv -> ClaimsSet
mkCustomClaimsWithNs ns e@LocalEnv {..} =
  addClaim (withNs "scope") (toJSON Login)
    $ addClaim (withNs "created")  (toJSON currentTimeUtc)
    $ addClaim (withNs "clientId") (toJSON uuid)
    $ addClaim (withNs "isRoot")   (toJSON flipBit)
    $ addClaim (withNs "userName") (toJSON shortPrintableText)
    $ baseClaimsSet e
  where withNs = T.append ns

signCustomClaimsWithNs :: (Alg, JWK) -> Benchmark
signCustomClaimsWithNs (a, k) =
  env localEnv $ bench "custom-claims-with-ns" . nfAppIO benchmark
 where
  benchmark = doSign a k . mkCustomClaimsWithNs "https://www.example.com/test"

decodeCustomClaimsWithNs :: (Alg, JWK) -> Benchmark
decodeCustomClaimsWithNs (a, k) =
  env (prepareToken (mkCustomClaimsWithNs "https://www.example.com/test") a k)
    $ bench "custom-claims-with-ns"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (Either JWTError (Text, Bool, UUID, UTCTime, Scope))
  benchmark token =
    runExceptT
      $   decodeCompact (fromStrict token)
      >>= verifyClaims (validation & issuerPredicate .~ (== "benchmarks")) k
      >>= except
      .   decodeJson (decodeData "https://www.example.com/test")

  decodeData ns claims =
    (,,,,)
      <$> fromJSON (claims ! withNs "userName")
      <*> fromJSON (claims ! withNs "isRoot")
      <*> fromJSON (claims ! withNs "clientId")
      <*> fromJSON (claims ! withNs "created")
      <*> fromJSON (claims ! withNs "scope")
    where withNs = T.append ns



mkComplexClaims :: BenchEnv -> ClaimsSet
mkComplexClaims e@LocalEnv {..} =
  addClaim "emails" (toJSON emailsList)
    $ addClaim
        "scopes"
        (toJSON
          [Login, Extended, UserRead, UserWrite, AccountRead, AccountWrite]
        )
    $ addClaim "accounts"  (toJSON accountList)
    $ addClaim "created"   (toJSON currentTimeUtc)
    $ addClaim "client_id" (toJSON uuid)
    $ addClaim "is_root"   (toJSON flipBit)
    $ addClaim "user_name" (toJSON shortPrintableText)
    $ baseClaimsSet e

signComplexClaims :: (Alg, JWK) -> Benchmark
signComplexClaims (a, k) =
  env localEnv $ bench "complex-claims" . nfAppIO benchmark
  where benchmark = doSign a k . mkComplexClaims

decodeComplexClaims :: (Alg, JWK) -> Benchmark
decodeComplexClaims (a, k) =
  env (prepareToken mkComplexClaims a k)
    $ bench "complex-claims"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString
    -> IO
         ( Either
             JWTError
             ( Text
             , Bool
             , UUID
             , UTCTime
             , NonEmpty (UUID, Text)
             , [Scope]
             , [String]
             )
         )
  benchmark token =
    runExceptT
      $   decodeCompact (fromStrict token)
      >>= verifyClaims (validation & issuerPredicate .~ (== "benchmarks")) k
      >>= except
      .   decodeJson decodeData

  decodeData claims =
    (,,,,,,)
      <$> fromJSON (claims ! "user_name")
      <*> fromJSON (claims ! "is_root")
      <*> fromJSON (claims ! "client_id")
      <*> fromJSON (claims ! "created")
      <*> fromJSON (claims ! "accounts")
      <*> fromJSON (claims ! "scopes")
      <*> fromJSON (claims ! "emails")



validation :: JWTValidationSettings
validation =
  defaultJWTValidationSettings (== "https://example.com")
    &  jwtValidationSettingsAllowedSkew
    .~ 5


