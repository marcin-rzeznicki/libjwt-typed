--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE CPP, ForeignFunctionInterface #-}
{-# LANGUAGE DerivingStrategies #-}

module Libjwt.FFI.Libjwt where

import Foreign.C.Types

newtype JwtAlgT = JwtAlg CInt
  deriving stock Eq

#include <jwt.h>

#{enum JwtAlgT, JwtAlg, JWT_ALG_NONE, JWT_ALG_HS256, JWT_ALG_HS384, JWT_ALG_HS512, JWT_ALG_RS256, JWT_ALG_RS384, JWT_ALG_RS512, JWT_ALG_ES256, JWT_ALG_ES384, JWT_ALG_ES512, JWT_ALG_TERM }
