--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MagicHash #-}

-- | Interface to C libraries 
module Libjwt.FFI.Jwt
  ( JwtIO
  , unsafePerformJwtIO
  , JwtT
  , mkJwtT
  , jwtDecode
  , jwtEncode
  , addGrant
  , addGrantBool
  , addGrantInt
  , addGrantInt64
  , addGrantsFromJson
  , jwtSetAlg
  , addHeader
  , getGrant
  , getGrantBool
  , getGrantInt
  , getGrantInt64
  , getGrantAsJson
  , jwtGetAlg
  , getHeader
  , unsafeAddGrant
  , unsafeAddGrantBool
  , unsafeAddGrantInt
  , unsafeAddGrantInt64
  , unsafeAddHeader
  , unsafeGetGrant
  , unsafeGetGrantBool
  , unsafeGetGrantInt
  , unsafeGetGrantInt64
  , unsafeGetGrantAsJson
  , unsafeGetHeader
  , JsonToken(..)
  , unsafeMapTokenizedJsonArray
  )
where

import           Libjwt.FFI.Libjwt
import           Libjwt.FFI.Jsmn

import           Control.Exception              ( throwIO )
import           Control.Monad                  ( void
                                                , (<=<)
                                                )

import           Control.Monad.Catch            ( MonadCatch
                                                , MonadThrow
                                                )

import           Control.Monad.Extra            ( whenMaybe
                                                , loopM
                                                )

import           Control.Monad.Trans.State.Strict
import           Control.Monad.Trans.Class      ( lift )

import           Data.ByteString                ( ByteString
                                                , useAsCString
                                                , packCString
                                                , packCStringLen
                                                )
import           Data.ByteString.Unsafe         ( unsafePackMallocCString
                                                , unsafeUseAsCStringLen
                                                )

import           Foreign                 hiding ( void )
import           Foreign.C.Types
import           Foreign.C.String
import           Foreign.C.Error

import           GHC.Base                       ( unpackCString# )
import           GHC.Exts

import           System.IO.Unsafe               ( unsafePerformIO )

-- | IO restricted to calling /libjwt/ and /jsmn/
newtype JwtIO a = JIO (IO a)
 deriving newtype (Functor, Applicative, Monad, MonadThrow, MonadCatch)

-- | Wrapped pointer to /jwt_t/ with managed lifetime
newtype JwtT = JwtT (ForeignPtr JwtT)

unsafePerformJwtIO :: JwtIO a -> a
unsafePerformJwtIO (JIO io) = unsafePerformIO io

mkJwtT :: JwtIO JwtT
mkJwtT = JIO $ mkJwtT_ "jwt_new" c_jwt_new

jwtDecode :: Maybe ByteString -> ByteString -> JwtIO JwtT
jwtDecode maybeKey token = JIO
  $ maybe ($ (nullPtr, 0)) unsafeUseAsCStringLen maybeKey doDecode
 where
  doDecode (p_key, key_len) = useAsCString token $ \p_token ->
    mkJwtT_ "jwt_decode"
      $ \ret -> c_jwt_decode ret p_token p_key $ fromIntegral key_len

mkJwtT_ :: String -> (Ptr PJwtT -> IO CInt) -> IO JwtT
mkJwtT_ loc ctr = alloca $ \ptr -> do
  res <- ctr ptr
  if res == 0 then wrapJwtPtr =<< peek ptr else throwLibjwt loc $ Errno res

type PJwtT = Ptr JwtT

{-# RULES
"addGrant/unsafeAddGrant" forall s . addGrant (unpackCString# s) = unsafeAddGrant s
"addGrantBool/unsafeAddGrantBool" forall s . addGrantBool (unpackCString# s) = unsafeAddGrantBool s
"addGrantInt64/unsafeAddGrantInt64" forall s . addGrantInt64 (unpackCString# s) = unsafeAddGrantInt64 s
"addGrantInt/unsafeAddGrantInt" forall s . addGrantInt (unpackCString# s) = unsafeAddGrantInt s
"addHeader/unsafeAddHeader" forall s . addHeader (unpackCString# s) = unsafeAddHeader s #-}

{-# INLINE [0] addGrant #-}
{-# INLINE [0] addGrantBool #-}
{-# INLINE [0] addGrantInt64 #-}
{-# INLINE [0] addGrantInt #-}
{-# INLINE [0] addHeader #-}

addGrant :: String -> ByteString -> JwtT -> JwtIO ()
addGrant grant val jwt = JIO $ useAsCString val $ \p_val ->
  _addGrant "jwt_add_grant" c_jwt_add_grant grant p_val jwt

unsafeAddGrant :: Addr# -> ByteString -> JwtT -> JwtIO ()
unsafeAddGrant p_grant val jwt = JIO $ useAsCString val $ \p_val ->
  _unsafeAddGrant "jwt_add_grant" c_jwt_add_grant p_grant p_val jwt

addGrantBool :: String -> Bool -> JwtT -> JwtIO ()
addGrantBool grant =
  coerce . _addGrant "jwt_add_grant_bool" c_jwt_add_grant_bool grant . fromBool

unsafeAddGrantBool :: Addr# -> Bool -> JwtT -> JwtIO ()
unsafeAddGrantBool p_grant =
  coerce
    . _unsafeAddGrant "jwt_add_grant_bool" c_jwt_add_grant_bool p_grant
    . fromBool

addGrantInt64 :: String -> Int64 -> JwtT -> JwtIO ()
addGrantInt64 grant =
  coerce . _addGrant "jwt_add_grant_int" c_jwt_add_grant_int grant . coerce

unsafeAddGrantInt64 :: Addr# -> Int64 -> JwtT -> JwtIO ()
unsafeAddGrantInt64 p_grant =
  coerce
    . _unsafeAddGrant "jwt_add_grant_int" c_jwt_add_grant_int p_grant
    . coerce

addGrantInt :: String -> Int -> JwtT -> JwtIO ()
addGrantInt grant =
  coerce
    . _addGrant "jwt_add_grant_int" c_jwt_add_grant_int grant
    . fromIntegral

unsafeAddGrantInt :: Addr# -> Int -> JwtT -> JwtIO ()
unsafeAddGrantInt p_grant =
  coerce
    . _unsafeAddGrant "jwt_add_grant_int" c_jwt_add_grant_int p_grant
    . fromIntegral

_addGrant
  :: String
  -> (PJwtT -> CString -> p -> IO CInt)
  -> String
  -> p
  -> JwtT
  -> IO ()
_addGrant loc f grant val (JwtT pjwt_t) = withForeignPtr pjwt_t $ \jwt ->
  withCAString grant $ \p_grant -> throwIfNonZero_ loc $ f jwt p_grant val

_unsafeAddGrant
  :: String -> (PJwtT -> CString -> p -> IO CInt) -> Addr# -> p -> JwtT -> IO ()
_unsafeAddGrant loc f p_grant val (JwtT pjwt_t) =
  withForeignPtr pjwt_t $ \jwt -> throwIfNonZero_ loc $ f jwt (Ptr p_grant) val

addGrantsFromJson :: ByteString -> JwtT -> JwtIO ()
addGrantsFromJson json (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  useAsCString json
    $ throwIfNonZero_ "jwt_add_grants_json"
    . c_jwt_add_grants_json jwt

jwtSetAlg :: JwtAlgT -> ByteString -> JwtT -> JwtIO ()
jwtSetAlg alg key (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  if alg == jwtAlgNone
    then void $ c_jwt_set_alg jwt jwtAlgNone nullPtr 0
    else unsafeUseAsCStringLen key $ \(p_key, keylen) ->
      throwIfNonZero_ "jwt_set_alg" $ c_jwt_set_alg jwt alg p_key $ fromIntegral
        keylen

addHeader :: String -> ByteString -> JwtT -> JwtIO ()
addHeader h val (JwtT pjwt_t) =
  JIO $ useAsCString val $ \p_val -> withForeignPtr pjwt_t $ \jwt ->
    withCAString h $ \ph ->
      throwIfNonZero_ "jwt_add_header" $ c_jwt_add_header jwt ph p_val

unsafeAddHeader :: Addr# -> ByteString -> JwtT -> JwtIO ()
unsafeAddHeader p_header val (JwtT pjwt_t) =
  JIO $ useAsCString val $ \p_val -> withForeignPtr pjwt_t $ \jwt ->
    throwIfNonZero_ "jwt_add_header" $ c_jwt_add_header jwt (Ptr p_header) p_val

jwtEncode :: JwtT -> JwtIO ByteString
jwtEncode (JwtT pjwt_t) =
  JIO
    $   withForeignPtr pjwt_t
    $   unsafePackMallocCString
    <=< throwErrnoIfNull "jwt_encode_str"
    .   c_jwt_encode_str

{-# RULES
"getGrant/unsafeGetGrant" forall s . getGrant (unpackCString# s) = unsafeGetGrant s
"getGrantBool/unsafeGetGrantBool" forall s . getGrantBool (unpackCString# s) = unsafeGetGrantBool s
"getGrantInt64/unsafeGetGrantInt64" forall s . getGrantInt64 (unpackCString# s) = unsafeGetGrantInt64 s
"getGrantInt/unsafeGetGrantInt" forall s . getGrantInt (unpackCString# s) = unsafeGetGrantInt s
"getGrantAsJson/unsafeGetGrantAsJson" forall s . getGrantAsJson (unpackCString# s) = unsafeGetGrantAsJson s
"getHeader/unsafeGetHeader" forall s . getHeader (unpackCString# s) = unsafeGetHeader s #-}

{-# INLINE [0] getGrant #-}
{-# INLINE [0] getGrantBool #-}
{-# INLINE [0] getGrantInt64 #-}
{-# INLINE [0] getGrantInt #-}
{-# INLINE [0] getGrantAsJson #-}
{-# INLINE [0] getHeader #-}

getGrant :: String -> JwtT -> JwtIO (Maybe ByteString)
getGrant grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString grant $ whenMaybeNotNull packCString . c_jwt_get_grant jwt

unsafeGetGrant :: Addr# -> JwtT -> JwtIO (Maybe ByteString)
unsafeGetGrant p_grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  whenMaybeNotNull packCString $ c_jwt_get_grant jwt $ Ptr p_grant

getGrantBool :: String -> JwtT -> JwtIO (Maybe Bool)
getGrantBool grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString grant
    $ throwErrnoOrNoEnt "jwt_get_grant_bool"
    . fmap toBool
    . c_jwt_get_grant_bool jwt

unsafeGetGrantBool :: Addr# -> JwtT -> JwtIO (Maybe Bool)
unsafeGetGrantBool p_grant (JwtT pjwt_t) =
  JIO $ withForeignPtr pjwt_t $ \jwt ->
    throwErrnoOrNoEnt "jwt_get_grant_bool"
      . fmap toBool
      . c_jwt_get_grant_bool jwt
      $ Ptr p_grant

getGrantInt64 :: String -> JwtT -> JwtIO (Maybe Int64)
getGrantInt64 grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString grant
    $ coerce
    . throwErrnoOrNoEnt "jwt_get_grant_int"
    . c_jwt_get_grant_int jwt

unsafeGetGrantInt64 :: Addr# -> JwtT -> JwtIO (Maybe Int64)
unsafeGetGrantInt64 p_grant (JwtT pjwt_t) =
  JIO $ withForeignPtr pjwt_t $ \jwt ->
    coerce
      . throwErrnoOrNoEnt "jwt_get_grant_int"
      . c_jwt_get_grant_int jwt
      $ Ptr p_grant


getGrantInt :: String -> JwtT -> JwtIO (Maybe Int)
getGrantInt grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString grant
    $ throwErrnoOrNoEnt "jwt_get_grant_int"
    . fmap (fromIntegral :: CLong -> Int)
    . c_jwt_get_grant_int jwt

unsafeGetGrantInt :: Addr# -> JwtT -> JwtIO (Maybe Int)
unsafeGetGrantInt p_grant (JwtT pjwt_t) =
  JIO $ withForeignPtr pjwt_t $ \jwt ->
    throwErrnoOrNoEnt "jwt_get_grant_int"
      . fmap (fromIntegral :: CLong -> Int)
      . c_jwt_get_grant_int jwt
      $ Ptr p_grant

getGrantAsJson :: String -> JwtT -> JwtIO (Maybe ByteString)
getGrantAsJson grant (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString grant
    $ whenMaybeNotNull unsafePackMallocCString
    . c_jwt_get_grants_json jwt

unsafeGetGrantAsJson :: Addr# -> JwtT -> JwtIO (Maybe ByteString)
unsafeGetGrantAsJson p_grant (JwtT pjwt_t) =
  JIO $ withForeignPtr pjwt_t $ \jwt -> do
    val <- c_jwt_get_grants_json jwt $ Ptr p_grant
    whenMaybe (val /= nullPtr) $ unsafePackMallocCString val

jwtGetAlg :: JwtT -> JwtIO JwtAlgT
jwtGetAlg (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t c_jwt_get_alg

getHeader :: String -> JwtT -> JwtIO (Maybe ByteString)
getHeader h (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  withCAString h $ whenMaybeNotNull packCString . c_jwt_get_header jwt

unsafeGetHeader :: Addr# -> JwtT -> JwtIO (Maybe ByteString)
unsafeGetHeader p_header (JwtT pjwt_t) = JIO $ withForeignPtr pjwt_t $ \jwt ->
  whenMaybeNotNull packCString $ c_jwt_get_header jwt $ Ptr p_header

foreign import ccall unsafe "jwt.h jwt_new" c_jwt_new :: Ptr PJwtT -> IO CInt
foreign import ccall unsafe "jwt.h &jwt_free" p_jwt_free :: FunPtr (PJwtT -> IO ())
foreign import ccall unsafe "jwt.h jwt_add_grant" c_jwt_add_grant :: PJwtT -> CString -> CString -> IO CInt
foreign import ccall unsafe "jwt.h jwt_add_grant_bool" c_jwt_add_grant_bool :: PJwtT -> CString -> CInt -> IO CInt
foreign import ccall unsafe "jwt.h jwt_add_grant_int" c_jwt_add_grant_int :: PJwtT -> CString -> CLong -> IO CInt
foreign import ccall unsafe "jwt.h jwt_add_grants_json" c_jwt_add_grants_json :: PJwtT -> CString -> IO CInt
foreign import ccall unsafe "jwt.h jwt_get_grant" c_jwt_get_grant :: PJwtT -> CString -> IO CString
foreign import ccall unsafe "jwt.h jwt_get_grant_bool" c_jwt_get_grant_bool :: PJwtT -> CString -> IO CInt
foreign import ccall unsafe "jwt.h jwt_get_grant_int" c_jwt_get_grant_int :: PJwtT -> CString -> IO CLong
foreign import ccall unsafe "jwt.h jwt_get_grants_json" c_jwt_get_grants_json :: PJwtT -> CString -> IO CString
foreign import ccall unsafe "jwt.h jwt_set_alg" c_jwt_set_alg :: PJwtT -> JwtAlgT -> CString -> CInt -> IO CInt
foreign import ccall unsafe "jwt.h jwt_add_header" c_jwt_add_header :: PJwtT -> CString -> CString -> IO CInt
foreign import ccall unsafe "jwt.h jwt_encode_str" c_jwt_encode_str :: PJwtT -> IO CString
foreign import ccall unsafe "jwt.h jwt_get_alg" c_jwt_get_alg :: PJwtT -> IO JwtAlgT
foreign import ccall unsafe "jwt.h jwt_get_header" c_jwt_get_header :: PJwtT ->  CString -> IO CString
foreign import ccall unsafe "jwt.h jwt_decode" c_jwt_decode :: Ptr PJwtT -> CString -> CString -> CInt -> IO CInt

type PJsmnTokT = Ptr JsmnTokT

-- | Low-level representation of JSON tokenization. Tokens are an exact representation of the underlying JSON, ie no conversions or unescaping has been performed.
--
--   The only exception is @JsStr@ which is already unquoted 
--   (@JsStr@ value is the string between the first and last quotation marks of the corresponding JSON string).
--
--   JSON objects are not parsed at all, but presented as one byte string (@JsBlob@).
data JsonToken = JsStr ByteString
               | JsNum ByteString
               | JsTrue
               | JsFalse
               | JsNull
               | JsArray [JsonToken]
               | JsBlob ByteString

foldrJson :: (JsonToken -> b -> b) -> b -> CString -> PJsmnTokT -> Int -> IO b
foldrJson f z p_js ptokens count = evalStateT (go f z count) 0
 where
  peekToken   = get >>= lift . peekElemOff ptokens
  offsetPlus1 = withStateT (+ 1)

  go :: (JsonToken -> a -> a) -> a -> Int -> StateT Int IO a
  go k a n
    | n == 0 = return a
    | otherwise = do
      tok <- peekToken
      case jsmnType tok of
        ttok
          | ttok == jsmnString
          -> k . JsStr <$> lift (pack tok) <*> offsetPlus1 (go k a (n - 1))
          | ttok == jsmnPrimitive
          -> k <$> lift (mkPrimToken tok) <*> offsetPlus1 (go k a (n - 1))
          | ttok == jsmnArray
          -> let len = fromIntegral $ size tok
             in  k . JsArray <$> offsetPlus1 (go (:) [] len) <*> go k a (n - 1)
          | otherwise
          -> let supertok = parent tok
             in  do
                   j <- get >>= lift . nextSibling supertok . (+ 1)
                   put j
                   k . JsBlob <$> lift (pack tok) <*> go k a (n - 1)

  mkPrimToken tok = do
    c <- peekByteOff p_js $ fromIntegral $ start tok
    case (c :: CChar) of
      116 -> return JsTrue
      110 -> return JsNull
      102 -> return JsFalse
      _   -> JsNum <$> pack tok

  pack tok =
    let s = start tok
        e = end tok
        n = e - s
    in  packCStringLen (p_js `plusPtr` fromIntegral s, fromIntegral n)

  nextSibling supertok = loopM
    (\j -> do
      let temp = advancePtr ptokens j
      t <- peekType temp
      p <- peekParent temp
      return $ if t == jsmnUndefined || p == supertok
        then Right j
        else Left (j + 1)
    )

unsafeUseTokenizedJsonArray
  :: (CString -> Ptr JsmnTokT -> Int -> IO a) -> ByteString -> IO (Maybe a)
unsafeUseTokenizedJsonArray f js =
  unsafeUseAsCStringLen js $ \(p_js, jslen) -> alloca $ \out -> do
    r <- c_tokenize_json p_js (fromIntegral jslen) out
    if r < 0
      then throwLibjwt "tokenize_json" (Errno $ negate r)
      else do
        ptokens <- peek out
        tok0    <- peek ptokens
        res     <- whenMaybe (jsmnType tok0 == jsmnArray)
          $ f p_js (advancePtr ptokens 1) (fromIntegral $ size tok0)
        free ptokens
        return res

unsafeMapTokenizedJsonArray
  :: (JsonToken -> b) -> ByteString -> JwtIO (Maybe [b])
unsafeMapTokenizedJsonArray f =
  JIO . unsafeUseTokenizedJsonArray (foldrJson ((:) . f) [])

foreign import ccall unsafe "tokenize_json" c_tokenize_json :: CString -> CSize -> Ptr PJsmnTokT -> IO CInt

wrapJwtPtr :: PJwtT -> IO JwtT
wrapJwtPtr = coerce . newForeignPtr p_jwt_free

throwIfNonZero_ :: String -> IO CInt -> IO ()
throwIfNonZero_ loc f = do
  res <- f
  if res == 0 then return () else throwLibjwt loc $ Errno res

whenMaybeNotNull :: (Ptr a -> IO b) -> IO (Ptr a) -> IO (Maybe b)
whenMaybeNotNull f io = do
  res <- io
  whenMaybe (res /= nullPtr) $ f res

throwLibjwt :: String -> Errno -> IO a
throwLibjwt loc err = throwIO $ errnoToIOError loc err Nothing Nothing

throwErrnoOrNoEnt :: String -> IO a -> IO (Maybe a)
throwErrnoOrNoEnt loc f = do
  res <- f
  err <- getErrno
  if err == eOK
    then return $ Just res
    else if err == eNOENT || err == eINVAL
      then return Nothing
      else throwLibjwt loc err
