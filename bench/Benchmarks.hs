
module Main
      ( main
      )
where

import           Algorithms
import           Benchmarks.Jose               as Jose
import           Benchmarks.Libjwt             as My

import           Criterion               hiding ( benchmark )
import           Criterion.Main                 ( defaultMain )

main :: IO ()
main = defaultMain
      [ bgroup
            "signing"
            [ bgroup
                  "HMAC512"
                  [ my $ mySigning <*> pure hs512
                  , jose $ joseSigning <*> pure jwkHS512
                  ]
            , bgroup
                  "RSA512"
                  [ my $ mySigning <*> pure rs512
                  , jose $ joseSigning <*> pure jwkRS512
                  ]
            , bgroup
                  "ECDSA256"
                  [ my $ mySigning <*> pure es256
                  , jose $ joseSigning <*> pure jwkES256
                  ]
            , bgroup
                  "ECDSA512"
                  [ my $ mySigning <*> pure es512
                  , jose $ joseSigning <*> pure jwkES512
                  ]
            ]
      , bgroup
            "decoding"
            [ bgroup
                  "HMAC512"
                  [ my $ myDecoding <*> pure hs512
                  , jose $ joseDecoding <*> pure jwkHS512
                  ]
            , bgroup
                  "RSA512"
                  [ my $ myDecoding <*> pure rs512
                  , jose $ joseDecoding <*> pure jwkRS512
                  ]
            , bgroup
                  "ECDSA256"
                  [ my $ myDecoding <*> pure es256
                  , jose $ joseDecoding <*> pure jwkES256
                  ]
            , bgroup
                  "ECDSA512"
                  [ my $ myDecoding <*> pure es512
                  , jose $ joseDecoding <*> pure jwkES512
                  ]
            ]
      ]
   where
      jose = bgroup "jose"
      joseSigning =
            [ Jose.signSimple
            , Jose.signCustomClaims
            , Jose.signCustomClaimsWithNs
            , Jose.signComplexClaims
            ]
      joseDecoding =
            [ Jose.decodeSimple
            , Jose.decodeCustomClaims
            , Jose.decodeCustomClaimsWithNs
            , Jose.decodeComplexClaims
            ]

      my = bgroup "libjwt"
      mySigning =
            [ My.signSimple
            , My.signCustomClaims
            , My.signWithNs
            , My.signComplexCustomClaims
            ]
      myDecoding =
            [ My.decodeSimple
            , My.decodeCustomClaims
            , My.decodeWithNs
            , My.decodeComplexCustomClaims
            ]
