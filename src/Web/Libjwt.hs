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
    , module Libjwt.Exceptions
    , module Libjwt.Header
    , module Libjwt.Keys
    , module Libjwt.Payload
    , module Libjwt.RegisteredClaims
    , module Libjwt.PrivateClaims
    , module Libjwt.JwtValidation
    , module Libjwt.NumericDate
    , module Libjwt.ASCII
    , module Libjwt.Flag
    , module Libjwt.Encoding
    , module Libjwt.Decoding
    )
where

import           Libjwt.ASCII                   ( ASCII(..) )
import           Libjwt.Decoding                ( Decode )
import           Libjwt.Encoding                ( Encode )
import           Libjwt.Exceptions
import           Libjwt.Flag                    ( Flag(..)
                                                , AFlag(..)
                                                )
import           Libjwt.Header
import           Libjwt.Jwt                     ( Jwt(..)
                                                , Encoded
                                                , getToken
                                                , sign
                                                , signJwt
                                                , Decoded
                                                , getDecoded
                                                , decodeString
                                                , decodeByteString
                                                , Validated
                                                , getValid
                                                , validateJwt
                                                , jwtFromString
                                                , jwtFromByteString
                                                )
import           Libjwt.JwtValidation    hiding ( runValidation
                                                , Valid
                                                , Check
                                                , invalid
                                                , valid
                                                , validation
                                                )
import           Libjwt.Keys
import           Libjwt.NumericDate             ( NumericDate(..)
                                                , fromUTC
                                                , fromPOSIX
                                                , plusSeconds
                                                )
import           Libjwt.Payload
import           Libjwt.PrivateClaims
import           Libjwt.RegisteredClaims

