{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}

module Env where

import           Web.Libjwt                     ( RsaKeyPair(..)
                                                , EcKeyPair(..)
                                                )

import           Control.Arrow                  ( left )

import           Control.Monad.Catch

import           Control.Monad.Time

import           Control.Monad.Trans.Reader     ( ReaderT
                                                , runReaderT
                                                )

import qualified Data.ByteString.Char8         as C8

import           Data.Either.Extra              ( fromEither )

import           Data.Time.Clock                ( UTCTime )
import           Data.Time.Clock.POSIX          ( POSIXTime
                                                , posixSecondsToUTCTime
                                                )

import           Data.UUID                      ( UUID )

import           Test.Hspec                     ( Expectation
                                                , expectationFailure
                                                , Spec
                                                )
import qualified Test.Hspec                    as HSpec


testJTI :: UUID
testJTI = read "5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25"

testRsa2048KeyPair :: RsaKeyPair
testRsa2048KeyPair =
  let privKey = C8.pack $ unlines
        [ "-----BEGIN RSA PRIVATE KEY-----"
        , "MIIEpgIBAAKCAQEAwCXp2P+qboao0tjUyU+D3YI+sgBn8dkGaxOvPFLBFQMNkhbL"
        , "0HEoRKNnQCubZNc0jXnMK5hCeGRnDS7lYclROXocRWUn5s2W3jP5xn7lM4otIpuE"
        , "3FStthMCrPSEQiBCXE4cyKiHaZqmbqXlHAHVEuGMM7oddiB6s3zjwf2h1v0SEiHf"
        , "5ZFzTVarStablqh6wVDAiYyM+8aUM0x9p3JcaWW+eDk/UU3jCfCke7R3t2rbD1ZC"
        , "j1cO08Uir3Lhf65TfU+iIrgLU3umV4B3gRcpd8iz0ZTLaG8Qnm0GsPQjR3PTZYEC"
        , "xEnFaRgXcQLHYYMAW9YaX6T3rlTGZAaP5YboxQIDAQABAoIBAQCg/OMBsauc8Ovv"
        , "xEX76MglxeM7hgWQ5vFus05lrzwgm686EClxme1QHMv8QszuXzSjuEFs4SQH9K82"
        , "p2z+UgrgqkOXjNoykVvvDgMe4OCuHv4T+dMGO1hTrXfXawKI2Lhg1/1bzX+u5ii9"
        , "mfbsUUixihHKoQvgFfRX/7JfrV50XZ3diwzd8DoEaIgeAIdyhLhVuh2W7wXbOF+l"
        , "aZW7gqCVzTBhC04E/D6eqFqvnkQyHzZPgaaDi4oL7gP8nGpcswlqKSLO5eVkkEHY"
        , "C88nAwU4Q/+qcAf09ijmTLlo07xLrLC0cOf2yQTwLj6ZffzTJ7NSMaPrTdEXThsW"
        , "wAeB/GcBAoGBAOzLST9/zakFGBTkwiLqgNVgEBUoYjB0Z+Fpx4qBLzKZNQP1yNup"
        , "LhC/4pIVQM+ZjOS0Wx7Sh0FTLHFb018quPiAPsKMEC2CW5v7vKwC4zW72/v5UrIw"
        , "pcBzl67nsc53r5Lblol9PU4oCjDzuFMjMbg+EzD3kVp/gxC9bRMwK3zBAoGBAM+7"
        , "nOV80uteB1ZXazccj6g0ANd2AyJY6gHfxD1CopvRReYm36wmG00HQ3jHZPUcsLQp"
        , "dWvWplRFprZlce0jl7HcB/8g5wUkErMop3KK5cA886HxsATNSl6rYghZGALqxm/a"
        , "+v2AKoZThns8QRYL5bsBD4kTQLEIwp7j6sNbBrkFAoGBAL6fL8o0gkUsWqSHO1mM"
        , "WkZrXMcLiW/kZbPqyb3QHUSoXStg818RpInLTwO2pEP7IpcCMdBwPn3yDPb8qv4T"
        , "kHBMHTnUMznPlRvO3aXDdVFOd9sybMYRr31sEJG250aExwx8RYVNEssWJI4fxST4"
        , "UhA1uJFU2uh1efdB5srpnjiBAoGBALTDCPAZAmCVXcUgJMe8LrWrKuBSbL/Cpz4i"
        , "PV0hUuZL4Is5YIEoV7FblLbQq2UvJgRf3zGLgwjp4vvsooo74pB+auby9pReo3cK"
        , "9UqS2wHBCC/vY7+J9CEU+SVSgbZoHWzQHH/iux5QKEGsWOaaS7nCXoZlHnHusYwZ"
        , "v/tmhh8RAoGBAIi3Lbup0AVwougANLXwMLCfT8HxI8Hozdr+Pe0ibTnjfY+BPuy1"
        , "vSgozXao68TwW3u58PcdvfBnfg/7XCK6TXtij48JDu6qw0IiSRxOZ5Ed/GW2P031"
        , "7TfwnjBohjM2O6NRne8qe6Qv5xLagoVKQfa1WhQEFU2bTNLYA/2kv266"
        , "-----END RSA PRIVATE KEY-----"
        ]
      pubKey = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwCXp2P+qboao0tjUyU+D"
        , "3YI+sgBn8dkGaxOvPFLBFQMNkhbL0HEoRKNnQCubZNc0jXnMK5hCeGRnDS7lYclR"
        , "OXocRWUn5s2W3jP5xn7lM4otIpuE3FStthMCrPSEQiBCXE4cyKiHaZqmbqXlHAHV"
        , "EuGMM7oddiB6s3zjwf2h1v0SEiHf5ZFzTVarStablqh6wVDAiYyM+8aUM0x9p3Jc"
        , "aWW+eDk/UU3jCfCke7R3t2rbD1ZCj1cO08Uir3Lhf65TfU+iIrgLU3umV4B3gRcp"
        , "d8iz0ZTLaG8Qnm0GsPQjR3PTZYECxEnFaRgXcQLHYYMAW9YaX6T3rlTGZAaP5Ybo"
        , "xQIDAQAB"
        , "-----END PUBLIC KEY-----"
        ]
  in  FromRsaPem { privKey, pubKey }

testEcP256KeyPair :: EcKeyPair
testEcP256KeyPair =
  let ecPrivKey = C8.pack $ unlines
        [ "-----BEGIN EC PRIVATE KEY-----"
        , "MHcCAQEEINQ0e0KOa3EZSB5RTd2xBuO3O7NNFietDIWl+B+R38LuoAoGCCqGSM49"
        , "AwEHoUQDQgAEKZL0X84AvdnGZdsIdAS60OnvF3FNlsrCnaXRoJUVdOYZldzb4po2"
        , "uDXF5W58DS8C31fV+z+0lTG5RvuAqfkdbA=="
        , "-----END EC PRIVATE KEY-----"
        ]
      ecPubKey = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKZL0X84AvdnGZdsIdAS60OnvF3FN"
        , "lsrCnaXRoJUVdOYZldzb4po2uDXF5W58DS8C31fV+z+0lTG5RvuAqfkdbA=="
        , "-----END PUBLIC KEY-----"
        ]
  in  FromEcPem { ecPrivKey, ecPubKey }

testEcP384KeyPair :: EcKeyPair
testEcP384KeyPair =
  let ecPrivKey = C8.pack $ unlines
        [ "-----BEGIN EC PRIVATE KEY-----"
        , "MIGkAgEBBDBo23gVhrmZIkAAUDzb1FK9Ajdv5ehXcTedZea0uW2xx6WK/VCyCLvv"
        , "XZXK77d7dPmgBwYFK4EEACKhZANiAAQT7mlkd/dKcTa7jxiClVEPS+b8BOpZZeft"
        , "h2GS5p6wR2qWt8eb9cxGWG8ArWbXHBKvX9BMoHOVgVhfVkdGPDD8GkU97gLP7jbW"
        , "A9lWwFMt6xEEGm/yKupVyZ9p9PAZaWU="
        , "-----END EC PRIVATE KEY-----"
        ]
      ecPubKey = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEE+5pZHf3SnE2u48YgpVRD0vm/ATqWWXn"
        , "7YdhkuaesEdqlrfHm/XMRlhvAK1m1xwSr1/QTKBzlYFYX1ZHRjww/BpFPe4Cz+42"
        , "1gPZVsBTLesRBBpv8irqVcmfafTwGWll"
        , "-----END PUBLIC KEY-----"
        ]
  in  FromEcPem { ecPrivKey, ecPubKey }

testEcP521KeyPair :: EcKeyPair
testEcP521KeyPair =
  let ecPrivKey = C8.pack $ unlines
        [ "-----BEGIN EC PRIVATE KEY-----"
        , "MIHcAgEBBEIAIWLn8LIw+NC3gZJIFemY/Ku5QNNncVjNZiQdICh7KzgHPrjCrdQk"
        , "2HNAZ+7r5biSu07Kucvn7OLbubL8iFykX8GgBwYFK4EEACOhgYkDgYYABAGgIDu0"
        , "FLPpH0NNAzlqrRW3IClcxSZt043iTdwLTmbMj51epCDDPb04jfdDWg58pQqXRKEI"
        , "xRUJbv/6aJimWkfkvwBsHhdkIdXSTID9wKTaCSkeGAqGdzjkBdTMA8sfEujYDtHt"
        , "FoCrBx31I4jnh2yX1WNa9oycus38E6IzWeTdq547aA=="
        , "-----END EC PRIVATE KEY-----"
        ]
      ecPubKey = C8.pack $ unlines
        [ "-----BEGIN PUBLIC KEY-----"
        , "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBoCA7tBSz6R9DTQM5aq0VtyApXMUm"
        , "bdON4k3cC05mzI+dXqQgwz29OI33Q1oOfKUKl0ShCMUVCW7/+miYplpH5L8AbB4X"
        , "ZCHV0kyA/cCk2gkpHhgKhnc45AXUzAPLHxLo2A7R7RaAqwcd9SOI54dsl9VjWvaM"
        , "nLrN/BOiM1nk3aueO2g="
        , "-----END PUBLIC KEY-----"
        ]
  in  FromEcPem { ecPrivKey, ecPubKey }


newtype TestEnv a = MkTest { runTest :: ReaderT UTCTime (Either SomeException) a }
  deriving newtype (Functor, Applicative, Monad, MonadTime, MonadThrow, MonadCatch)

pass :: TestEnv Expectation
pass = MkTest (pure alwaysTrue) where alwaysTrue = pure ()

presetTime :: UTCTime
presetTime = posixSecondsToUTCTime 1595386660

runTestWithPresetTime :: TestEnv a -> Either SomeException a
runTestWithPresetTime = runTestWithGivenTime presetTime

runTestWithGivenTime :: UTCTime -> TestEnv a -> Either SomeException a
runTestWithGivenTime time = ($ time) . runReaderT . runTest

specify :: String -> TestEnv Expectation -> Spec
specify name = HSpec.specify name . runExpectationWithPresetTime

specifyWithTime :: POSIXTime -> String -> TestEnv Expectation -> Spec
specifyWithTime t0 name =
  HSpec.specify name . runExpectationWithTime (posixSecondsToUTCTime t0)

xspecify :: String -> TestEnv Expectation -> Spec
xspecify name = HSpec.xspecify name . runExpectationWithPresetTime

runExpectationWithPresetTime :: TestEnv Expectation -> Expectation
runExpectationWithPresetTime = runExpectationWithTime presetTime

runExpectationWithTime :: UTCTime -> TestEnv Expectation -> Expectation
runExpectationWithTime t0 =
  fromEither
    . left
        (\e ->
          expectationFailure
            $  "unexpected exception thrown while running the test: "
            ++ displayException e
        )
    . runTestWithGivenTime t0


