module Interop.JWTHelpers
  ( mkSigner
  , mkJWTAlgorithm
  )
where

import           Web.Libjwt                     ( Alg(..)
                                                , RsaKeyPair(..)
                                                , Secret(..)
                                                )

import           Data.Maybe                     ( fromMaybe )

import qualified Web.JWT                       as JWT

mkSigner :: Alg -> Maybe JWT.Signer
mkSigner (HS256 secret) = Just $ JWT.HMACSecret $ reveal secret
mkSigner (RS256 pem   ) = Just $ mkRSAPrivateKey pem
mkSigner None           = Nothing
mkSigner _              = error "Unsupported alg"

mkRSAPrivateKey :: RsaKeyPair -> JWT.Signer
mkRSAPrivateKey pem =
  JWT.RSAPrivateKey
    $ fromMaybe (error $ "JWT.readRsaSecret on\n" ++ show pem)
    $ JWT.readRsaSecret
    $ privKey pem

mkJWTAlgorithm :: Alg -> Maybe JWT.Algorithm
mkJWTAlgorithm None      = Nothing
mkJWTAlgorithm (HS256 _) = Just JWT.HS256
mkJWTAlgorithm (RS256 _) = Just JWT.RS256
mkJWTAlgorithm _         = error "Unsupported algorithm"
