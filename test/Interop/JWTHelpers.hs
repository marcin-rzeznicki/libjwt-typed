{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

module Interop.JWTHelpers
  ( mkSigner
  , SomeAlgorithm(..)
  , hmac256
  , none
  , rsa256
  , toHeaderAlg
  )
where

import           Web.Libjwt                     ( Algorithm(..)
                                                , SigningKey(..)
                                                , Secret(..)
                                                )
import           Libjwt.Algorithms              ( toHeaderAlg )

import qualified Env                           as E

import           Data.Maybe                     ( fromMaybe )

import qualified Web.JWT                       as JWT

data SomeAlgorithm = forall k . SigningKey k => SomeAlgorithm (Algorithm k)

hmac256 :: SomeAlgorithm
hmac256 =
  SomeAlgorithm
    $ HMAC256
        "MWNmYzExODA5OWFjOGM3NDNmMmM5Zjg5ZDc0YTM3M2VhMGNkMzA2MDY3ZjFhZDk5N2I3OTc5Yjdm\
        \NDg3NDBkMiAgLQo"

none :: SomeAlgorithm
none = SomeAlgorithm AlgNone

rsa256 :: SomeAlgorithm
rsa256 = SomeAlgorithm $ RSA256 E.testRsa2048KeyPair

mkSigner :: SomeAlgorithm -> Maybe JWT.Signer
mkSigner (SomeAlgorithm (HMAC256 secret)) =
  Just $ JWT.HMACSecret $ reveal secret
mkSigner (SomeAlgorithm (RSA256 pem)) = Just $ mkRSAPrivateKey pem
mkSigner (SomeAlgorithm AlgNone     ) = Nothing
mkSigner _                            = error "Unsupported alg"

mkRSAPrivateKey :: SigningKey k => k -> JWT.Signer
mkRSAPrivateKey k =
  let rsaSecret = getSigningKey k
  in  JWT.RSAPrivateKey
        $ fromMaybe (error $ "JWT.readRsaSecret on\n" ++ show rsaSecret)
        $ JWT.readRsaSecret rsaSecret
