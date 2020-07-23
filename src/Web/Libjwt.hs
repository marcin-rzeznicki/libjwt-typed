--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{- |
Copyright: (c) 2020 Marcin Rzeźnicki
SPDX-License-Identifier: MPL-2.0
Maintainer: Marcin Rzeźnicki <marcin.rzeznicki@gmail.com>

A typesafe and idiomatic Haskell wrapper over libjwt
-}

module Web.Libjwt
       ( module Libjwt.Jwt
       , Alg(..)
       , Typ(..)
       , Header(..)
       , module Libjwt.Keys
       , module Libjwt.RegisteredClaims
       , module Libjwt.PrivateClaims
       , module Libjwt.Payload
       , ValidationSettings(..)
       , defaultValidationSettings
       , ValidationNEL
       , ValidationFailure(..)
       , JwtValidation
       , checkIssuer
       , checkSubject
       , checkAge
       , checkIssuedAfter
       , checkJwtId
       , checkClaim
       , check
       , Encode
       , Decode
       , module Libjwt.Exceptions
       , NumericDate(..)
       , fromUTC
       , fromPOSIX
       , ASCII(..)
       , module Libjwt.Flag
       )
where

import           Libjwt.ASCII
import           Libjwt.Decoding
import           Libjwt.Encoding
import           Libjwt.Exceptions
import           Libjwt.Flag
import           Libjwt.Header
import           Libjwt.Jwt
import           Libjwt.JwtValidation
import           Libjwt.Keys
import           Libjwt.NumericDate
import           Libjwt.Payload
import           Libjwt.PrivateClaims
import           Libjwt.RegisteredClaims

