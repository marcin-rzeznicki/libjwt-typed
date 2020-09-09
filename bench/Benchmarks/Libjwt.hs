{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Benchmarks.Libjwt
  ( signSimple
  , signCustomClaims
  , signWithNs
  , signComplexCustomClaims
  , decodeSimple
  , decodeCustomClaims
  , decodeWithNs
  , decodeComplexCustomClaims
  )
where

import           Web.Libjwt
import           Benchmarks.Data
import           Env

import           Criterion                      ( Benchmark
                                                , bench
                                                , env
                                                , nf
                                                , whnfAppIO
                                                )

import           Data.ByteString                ( ByteString )

import           Data.Default

import           Data.List.NonEmpty             ( NonEmpty )

import           Data.Text                      ( Text )

import           Data.Time.Clock                ( UTCTime )

import           Data.UUID                      ( UUID )

import           Prelude                 hiding ( exp )

basePayload :: BenchEnv -> Payload Empty 'NoNs
basePayload LocalEnv {..} = def { iss = Iss (Just "benchmarks")
                                , aud = Aud ["https://example.com"]
                                , sub = Sub (Just subject)
                                , iat = Iat (Just $ fromPOSIX currentTime)
                                , exp = Exp (Just $ fromPOSIX someFutureTime)
                                , nbf = Nbf (Just $ fromPOSIX currentTime)
                                }

prepareToken
  :: Encode (PrivateClaims pc ns)
  => Alg
  -> (Alg -> BenchEnv -> Jwt pc ns)
  -> IO ByteString
prepareToken a jwt = getToken . signJwt . jwt a <$> localEnv



type SimpleJwt = Jwt Empty 'NoNs

mkSimpleJwt :: Alg -> BenchEnv -> SimpleJwt
mkSimpleJwt a e = Jwt { header = Header a JWT, payload = basePayload e }

signSimple :: Alg -> Benchmark
signSimple a = env localEnv $ bench "simple" . nf benchmark
  where benchmark = getToken . signJwt . mkSimpleJwt a

decodeSimple :: Alg -> Benchmark
decodeSimple a =
  env (prepareToken a mkSimpleJwt) $ bench "simple" . whnfAppIO benchmark
 where
  benchmark :: ByteString -> IO (ValidationNEL ValidationFailure SimpleJwt)
  benchmark =
    fmap (fmap getValid)
      . jwtFromByteString validationSettings (checkIssuer "benchmarks") a



type CustomJwt
  = Jwt
      '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID, "created" ->> UTCTime, "scope" ->> Flag Scope]
      'NoNs

mkCustomJwt :: Alg -> BenchEnv -> CustomJwt
mkCustomJwt a e@LocalEnv {..} = Jwt
  { header  = Header a JWT
  , payload = (basePayload e)
                { privateClaims = toPrivateClaims
                                    ( #userName ->> shortPrintableText
                                    , #isRoot ->> flipBit
                                    , #clientId ->> uuid
                                    , #created ->> currentTimeUtc
                                    , #scope ->> Flag Login
                                    )
                }
  }

signCustomClaims :: Alg -> Benchmark
signCustomClaims a = env localEnv $ bench "custom-claims" . nf benchmark
  where benchmark = getToken . signJwt . mkCustomJwt a

decodeCustomClaims :: Alg -> Benchmark
decodeCustomClaims a =
  env (prepareToken a mkCustomJwt) $ bench "custom-claims" . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (ValidationNEL ValidationFailure (Validated CustomJwt))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



type CustomJwtWithNs
  = Jwt
      '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID, "created" ->> UTCTime, "scope" ->> Flag Scope]
      ( 'SomeNs "https://www.example.com/test")

mkCustomJwtWithNs :: Alg -> BenchEnv -> CustomJwtWithNs
mkCustomJwtWithNs a e@LocalEnv {..} = Jwt
  { header  = Header a JWT
  , payload = (basePayload e)
                { privateClaims = toPrivateClaims $ withNs
                                    (Ns @"https://www.example.com/test")
                                    ( #userName ->> shortPrintableText
                                    , #isRoot ->> flipBit
                                    , #clientId ->> uuid
                                    , #created ->> currentTimeUtc
                                    , #scope ->> Flag Login
                                    )
                }
  }

signWithNs :: Alg -> Benchmark
signWithNs a = env localEnv $ bench "custom-claims-with-ns" . nf benchmark
  where benchmark = getToken . signJwt . mkCustomJwtWithNs a

decodeWithNs :: Alg -> Benchmark
decodeWithNs a =
  env (prepareToken a mkCustomJwtWithNs)
    $ bench "custom-claims-with-ns"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString
    -> IO (ValidationNEL ValidationFailure (Validated CustomJwtWithNs))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



type ComplexJwt
  = Jwt
      '["user_name" ->> Text, "is_root" ->> Bool, "client_id" ->> UUID, "created" ->> UTCTime, "accounts" ->> NonEmpty (UUID, Text), "scopes" ->> [Flag Scope], "emails" ->> [String]]
      'NoNs

mkComplexJwt :: Alg -> BenchEnv -> ComplexJwt
mkComplexJwt a e@LocalEnv {..} = Jwt
  { header  = Header a JWT
  , payload = (basePayload e)
                { privateClaims = toPrivateClaims
                                    ( #user_name ->> shortPrintableText
                                    , #is_root ->> flipBit
                                    , #client_id ->> uuid
                                    , #created ->> currentTimeUtc
                                    , #accounts ->> accountList
                                    , #scopes
                                      ->> [ Flag Login
                                          , Flag Extended
                                          , Flag UserRead
                                          , Flag UserWrite
                                          , Flag AccountRead
                                          , Flag AccountWrite
                                          ]
                                    , #emails ->> emailsList
                                    )
                }
  }

signComplexCustomClaims :: Alg -> Benchmark
signComplexCustomClaims a =
  env localEnv $ bench "complex-claims" . nf benchmark
  where benchmark = getToken . signJwt . mkComplexJwt a

decodeComplexCustomClaims :: Alg -> Benchmark
decodeComplexCustomClaims a =
  env (prepareToken a mkComplexJwt)
    $ bench "complex-claims"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (ValidationNEL ValidationFailure (Validated ComplexJwt))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



validationSettings :: ValidationSettings
validationSettings =
  defaultValidationSettings { appName = Just "https://example.com", leeway = 5 }
