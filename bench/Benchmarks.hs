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
                  [ my $ My.signing <*> pure hs512
                  , jose $ Jose.signing <*> pure jwkHS512
                  ]
            , bgroup
                  "RSA512"
                  [ my $ My.signing <*> pure rs512
                  , jose $ Jose.signing <*> pure jwkRS512
                  ]
            , bgroup
                  "ECDSA256"
                  [ my $ My.signing <*> pure es256
                  , jose $ Jose.signing <*> pure jwkES256
                  ]
            , bgroup
                  "ECDSA512"
                  [ my $ My.signing <*> pure es512
                  , jose $ Jose.signing <*> pure jwkES512
                  ]
            ]
      , bgroup
            "decoding"
            [ bgroup
                  "HMAC512"
                  [ my $ My.decoding <*> pure hs512
                  , jose $ Jose.decoding <*> pure jwkHS512
                  ]
            , bgroup
                  "RSA512"
                  [ my $ My.decoding <*> pure rs512
                  , jose $ Jose.decoding <*> pure jwkRS512
                  ]
            , bgroup
                  "ECDSA256"
                  [ my $ My.decoding <*> pure es256
                  , jose $ Jose.decoding <*> pure jwkES256
                  ]
            , bgroup
                  "ECDSA512"
                  [ my $ My.decoding <*> pure es512
                  , jose $ Jose.decoding <*> pure jwkES512
                  ]
            ]
      ]
   where
      jose = bgroup "jose"
      my   = bgroup "libjwt"
