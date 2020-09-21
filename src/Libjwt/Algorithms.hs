--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

-- | Algorithms used to sign and validate JWT signatures
module Libjwt.Algorithms
  ( Algorithm(..)
  , RsaKey
  , EcKey
  , toHeaderAlg
  , jwtAlgWithKey
  )
where

import           Libjwt.Header                  ( Alg(..) )
import           Libjwt.FFI.Libjwt
import           Libjwt.Keys

import           Data.Kind                      ( Constraint )

import           GHC.TypeLits

-- | Cryptographic algorithm used to secure the JWT
data Algorithm k where
  -- | HMAC SHA-256 (secret key must be __at least 256 bits in size__)
  HMAC256  ::Secret  -> Algorithm Secret
  -- | HMAC SHA-384 (secret key must be __at least 384 bits in size__)
  HMAC384  ::Secret  -> Algorithm Secret
  -- | HMAC SHA-512 (secret key must be __at least 512 bits in size__)
  HMAC512  ::Secret  -> Algorithm Secret
  -- | RSASSA-PKCS1-v1_5 SHA-256 (a key of size __2048 bits or larger__ must be used with this algorithm)
  RSA256   ::RsaKey r => r -> Algorithm r
  -- | RSASSA-PKCS1-v1_5 SHA-384 (a key of size __2048 bits or larger__ must be used with this algorithm) 
  RSA384   ::RsaKey r => r -> Algorithm r
  -- | RSASSA-PKCS1-v1_5 SHA-512 (a key of size __2048 bits or larger__ must be used with this algorithm)
  RSA512   ::RsaKey r => r -> Algorithm r
  -- | ECDSA with P-256 curve and SHA-256
  ECDSA256 ::EcKey e  => e -> Algorithm e
  -- | ECDSA with P-384 curve and SHA-384
  ECDSA384 ::EcKey e  => e -> Algorithm e
  -- | ECDSA with P-521 curve and SHA-512
  ECDSA512 ::EcKey e  => e -> Algorithm e
  -- | None
  AlgNone  ::Algorithm ()

deriving stock instance Show k => Show (Algorithm k)

type family RsaKey t :: Constraint where
  RsaKey RsaKeyPair = ()
  RsaKey RsaPubKey  = ()
  RsaKey a          = TypeError ('Text "RSASSA-PKCS-v1_5 cannot be used with " ':<>: 'ShowType a)

type family EcKey t :: Constraint where
  EcKey EcKeyPair = ()
  EcKey EcPubKey  = ()
  EcKey a         = TypeError ('Text "ECDSA cannot be used with " ':<>: 'ShowType a)

jwtAlgWithKey :: Algorithm k -> (JwtAlgT, k)
jwtAlgWithKey (HMAC256  secret) = (jwtAlgHs256, secret)
jwtAlgWithKey (HMAC384  secret) = (jwtAlgHs384, secret)
jwtAlgWithKey (HMAC512  secret) = (jwtAlgHs512, secret)
jwtAlgWithKey (RSA256   key   ) = (jwtAlgRs256, key)
jwtAlgWithKey (RSA384   key   ) = (jwtAlgRs384, key)
jwtAlgWithKey (RSA512   key   ) = (jwtAlgRs512, key)
jwtAlgWithKey (ECDSA256 key   ) = (jwtAlgEs256, key)
jwtAlgWithKey (ECDSA384 key   ) = (jwtAlgEs384, key)
jwtAlgWithKey (ECDSA512 key   ) = (jwtAlgEs512, key)
jwtAlgWithKey AlgNone           = (jwtAlgNone, ())

-- | Get the header parameter "alg" from the algorithm
--
-- +------------+-----------+
-- |Algorithm   |  'alg'    |   
-- +============+===========+
-- |'HMAC256'   |  'HS256'  |
-- +------------+-----------+
-- |'HMAC384'   |  'HS384'  |
-- +------------+-----------+
-- |'HMAC512'   |  'HS512'  |
-- +------------+-----------+
-- |'RSA256'    |  'RS256'  | 
-- +------------+-----------+
-- |'RSA384'    |  'RS384'  |
-- +------------+-----------+
-- |'RSA512'    |  'RS512'  |
-- +------------+-----------+
-- |'ECDSA256'  |  'ES256'  |
-- +------------+-----------+
-- |'ECDSA384'  |  'ES384'  |
-- +------------+-----------+
-- |'ECDSA512'  |  'ES512'  |
-- +------------+-----------+
--
toHeaderAlg :: Algorithm k -> Alg
toHeaderAlg (HMAC256  _) = HS256
toHeaderAlg (HMAC384  _) = HS384
toHeaderAlg (HMAC512  _) = HS512
toHeaderAlg (RSA256   _) = RS256
toHeaderAlg (RSA384   _) = RS384
toHeaderAlg (RSA512   _) = RS512
toHeaderAlg (ECDSA256 _) = ES256
toHeaderAlg (ECDSA384 _) = ES384
toHeaderAlg (ECDSA512 _) = ES512
toHeaderAlg AlgNone      = None
