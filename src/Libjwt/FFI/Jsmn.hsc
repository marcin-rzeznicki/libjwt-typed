--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE CPP, ForeignFunctionInterface #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Libjwt.FFI.Jsmn where

import Foreign
import Foreign.C.Types

data JsmnTokT = Token { jsmnType :: JsmnTypeT, start :: CInt, end :: CInt, size :: CInt, parent :: CInt }

peekType :: Ptr JsmnTokT -> IO JsmnTypeT
peekType ptr = peekByteOff ptr (#offset jsmntok_t, type)

peekParent :: Ptr JsmnTokT -> IO CInt
peekParent ptr = peekByteOff ptr (#offset jsmntok_t, parent)

instance Storable JsmnTokT where
  sizeOf    _ = (#size jsmntok_t)
  alignment _ = (#alignment jsmntok_t)

  peek ptr = Token 
    <$> (#peek jsmntok_t, type) ptr 
    <*> (#peek jsmntok_t, start) ptr 
    <*> (#peek jsmntok_t, end) ptr
    <*> (#peek jsmntok_t, size) ptr
    <*> (#peek jsmntok_t, parent) ptr

  poke ptr (Token (JsmnType t) st e sz p) = do
    (#poke jsmntok_t, type) ptr t
    (#poke jsmntok_t, start) ptr st
    (#poke jsmntok_t, end) ptr e
    (#poke jsmntok_t, size) ptr sz
    (#poke jsmntok_t, parent) ptr p

newtype JsmnTypeT = JsmnType CInt
  deriving stock Eq
  deriving newtype Storable

#include "jsmn.h"

#{enum JsmnTypeT, JsmnType, JSMN_UNDEFINED, JSMN_OBJECT, JSMN_ARRAY, JSMN_STRING, JSMN_PRIMITIVE }
