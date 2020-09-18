{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Benchmarks.Libjwt
  ( signing, decoding
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

signing :: SigningKey k => [Algorithm k -> Benchmark]
signing =
  [ signSimple
  , signCustomClaims
  , signWithNs
  , signComplexCustomClaims
  ]

decoding :: SigningKey k => [Algorithm k -> Benchmark]
decoding =
  [ decodeSimple
  , decodeCustomClaims
  , decodeWithNs
  , decodeComplexCustomClaims
  ]

basePayload :: BenchEnv -> Payload Empty 'NoNs
basePayload LocalEnv {..} = def { iss = Iss (Just "benchmarks")
                                , aud = Aud ["https://example.com"]
                                , sub = Sub (Just subject)
                                , iat = Iat (Just $ fromPOSIX currentTime)
                                , exp = Exp (Just $ fromPOSIX someFutureTime)
                                , nbf = Nbf (Just $ fromPOSIX currentTime)
                                }

prepareToken
  :: (SigningKey k, Encode (PrivateClaims pc ns))
  => Algorithm k
  -> (BenchEnv -> Payload pc ns)
  -> IO ByteString
prepareToken a mkPayload = getToken . sign a . mkPayload <$> localEnv



type SimpleJwt = Jwt Empty 'NoNs

signSimple :: SigningKey k => Algorithm k -> Benchmark
signSimple a = env localEnv $ bench "simple" . nf benchmark
  where benchmark = getToken . sign a . basePayload

decodeSimple :: SigningKey k => Algorithm k -> Benchmark
decodeSimple a =
  env (prepareToken a basePayload) $ bench "simple" . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (ValidationNEL ValidationFailure (Validated SimpleJwt))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



type CustomJwt
  = Jwt
      '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID, "created" ->> UTCTime, "scope" ->> Flag Scope]
      'NoNs

customPayload :: BenchEnv
                   -> Payload
                        '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID,
                          "created" ->> UTCTime, "scope" ->> Flag Scope]
                        'NoNs
customPayload e@LocalEnv {..} = (basePayload e)
  { privateClaims = toPrivateClaims
                      ( #userName ->> shortPrintableText
                      , #isRoot ->> flipBit
                      , #clientId ->> uuid
                      , #created ->> currentTimeUtc
                      , #scope ->> Flag Login
                      )
  }

signCustomClaims :: SigningKey k => Algorithm k -> Benchmark
signCustomClaims a = env localEnv $ bench "custom-claims" . nf benchmark
  where benchmark = getToken . sign a . customPayload

decodeCustomClaims :: SigningKey k => Algorithm k -> Benchmark
decodeCustomClaims a =
  env (prepareToken a customPayload)
    $ bench "custom-claims"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (ValidationNEL ValidationFailure (Validated CustomJwt))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



type CustomJwtWithNs
  = Jwt
      '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID, "created" ->> UTCTime, "scope" ->> Flag Scope]
      ( 'SomeNs "https://www.example.com/test")

customPayloadWithNs :: BenchEnv
                         -> Payload
                              '["userName" ->> Text, "isRoot" ->> Bool, "clientId" ->> UUID,
                                "created" ->> UTCTime, "scope" ->> Flag Scope]
                              ('SomeNs "https://www.example.com/test")
customPayloadWithNs e@LocalEnv {..} = (basePayload e)
  { privateClaims = toPrivateClaims $ withNs
                      (Ns @"https://www.example.com/test")
                      ( #userName ->> shortPrintableText
                      , #isRoot ->> flipBit
                      , #clientId ->> uuid
                      , #created ->> currentTimeUtc
                      , #scope ->> Flag Login
                      )
  }

signWithNs :: SigningKey k => Algorithm k -> Benchmark
signWithNs a = env localEnv $ bench "custom-claims-with-ns" . nf benchmark
  where benchmark = getToken . sign a . customPayloadWithNs

decodeWithNs :: SigningKey k => Algorithm k -> Benchmark
decodeWithNs a =
  env (prepareToken a customPayloadWithNs)
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

complexPayload :: BenchEnv
                    -> Payload
                         '["user_name" ->> Text, "is_root" ->> Bool, "client_id" ->> UUID,
                           "created" ->> UTCTime, "accounts" ->> NonEmpty (UUID, Text),
                           "scopes" ->> [Flag Scope], "emails" ->> [String]]
                         'NoNs
complexPayload e@LocalEnv {..} = (basePayload e)
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

signComplexCustomClaims :: SigningKey k => Algorithm k -> Benchmark
signComplexCustomClaims a =
  env localEnv $ bench "complex-claims" . nf benchmark
  where benchmark = getToken . sign a . complexPayload

decodeComplexCustomClaims :: SigningKey k => Algorithm k -> Benchmark
decodeComplexCustomClaims a =
  env (prepareToken a complexPayload)
    $ bench "complex-claims"
    . whnfAppIO benchmark
 where
  benchmark
    :: ByteString -> IO (ValidationNEL ValidationFailure (Validated ComplexJwt))
  benchmark = jwtFromByteString validationSettings (checkIssuer "benchmarks") a



validationSettings :: ValidationSettings
validationSettings =
  defaultValidationSettings { appName = Just "https://example.com", leeway = 5 }
