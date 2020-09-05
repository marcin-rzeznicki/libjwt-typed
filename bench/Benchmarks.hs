
module Main
      ( main
      )
where

import           Algorithms
import           Benchmarks.Jose               as Jose
import           Benchmarks.Libjwt             as My

import           Web.Libjwt

import           Criterion               hiding ( benchmark )
import           Criterion.Main                 ( defaultMain )

import qualified Crypto.JOSE.JWA.JWS           as Jose


main :: IO ()
main = defaultMain
      [ bgroup
            "signJwt"
            [ bgroup "libjwt"
            $   bgroupPerAlg
                      [ My.signSimple
                      , My.signCustomClaims
                      , My.signWithNs
                      , My.signComplexCustomClaims
                      ]
            <$> algorithms
            , bgroup "jose"
            $   bgroupPerJwkAlg
                      [ Jose.signSimple
                      , Jose.signCustomClaims
                      , Jose.signCustomClaimsWithNs
                      , Jose.signComplexClaims
                      ]
            <$> jwk_algorithms
            ]
      , bgroup
            "decodeJwt"
            [ bgroup "libjwt"
            $   bgroupPerAlg
                      [ My.decodeSimple
                      , My.decodeCustomClaims
                      , My.decodeWithNs
                      , My.decodeComplexCustomClaims
                      ]
            <$> algorithms
            , bgroup "jose"
            $   bgroupPerJwkAlg
                      [ Jose.decodeSimple
                      , Jose.decodeCustomClaims
                      , Jose.decodeCustomClaimsWithNs
                      , Jose.decodeComplexClaims
                      ]
            <$> jwk_algorithms
            ]
      ]
   where
      algorithms     = [hs512, rs512, es256, es512]
      jwk_algorithms = [jwkHS512, jwkRS512, jwkES256, jwkES512]

      bgroupPerAlg bs a = bgroup (formatAlg a) $ bs <*> pure a

      bgroupPerJwkAlg bs (a, k) = bgroup (formatJwkAlg a) $ bs <*> pure (a, k)

      formatAlg (HS256 _) = "HMAC using SHA-256"
      formatAlg (HS384 _) = "HMAC using SHA-384"
      formatAlg (HS512 _) = "HMAC using SHA-512"
      formatAlg (RS256 _) = "RSASSA-PKCS1-v1_5 using SHA-256"
      formatAlg (RS384 _) = "RSASSA-PKCS1-v1_5 using SHA-384"
      formatAlg (RS512 _) = "RSASSA-PKCS1-v1_5 using SHA-512"
      formatAlg (ES256 _) = "ECDSA using P-256 and SHA-256"
      formatAlg (ES384 _) = "ECDSA using P-384 and SHA-384"
      formatAlg (ES512 _) = "ECDSA using P-521 and SHA-512"
      formatAlg None      = "none"

      formatJwkAlg Jose.HS512 = "HMAC using SHA-512"
      formatJwkAlg Jose.RS512 = "RSASSA-PKCS1-v1_5 using SHA-512"
      formatJwkAlg Jose.ES256 = "ECDSA using P-256 and SHA-256"
      formatJwkAlg Jose.ES512 = "ECDSA using P-521 and SHA-512"
      formatJwkAlg _          = "not used"
