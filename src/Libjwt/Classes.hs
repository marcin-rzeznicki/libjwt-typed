--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_HADDOCK show-extensions #-}

{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

-- | The classes in this module are responsible for encoding and decoding values into JWT objects.
--
-- = Encoding
--
--   The encoders are divided into three groups:
--
--       * /Native/ - types: ByteString, Bool, Int, NumericDate and 'JsonByteString'.
--         They are encoded by simply calling the appropriate FFI function
--       * /Derived/ - types for which there is an instance of 'JwtRep'.
--         They are converted via 'rep' (transitively) to something we know how to encode
--       * /Specialized/ - 'Maybe' and lists
--
-- == JwtRep typeclass and derived encoders
--
--   This typeclass converts a value to its encodable representation. E.g.,
--   to encode 'UUID' we first convert it to something we know how to encode (ByteString).
--     
-- @
-- instance 'JwtRep' ByteString UUID where
--   rep = UUID.toASCIIBytes
-- @
--
--   This is an example of /derived/ encoder that calls 'rep' and then uses a different encoder (native) to perform the actual encoding.
--   This is sufficent to encode any single 'UUID' as 'ByteString' is natively supported.
--   Native encoders automatically take care of converting values to JSON format (escaping, quoting, UTF-8 encoding etc).
--
--   You can use the same method to extend the library to __support your type__.
--
-- @
-- newtype UserName = Un { toText :: Text }
--  deriving stock (Show, Eq)
--
-- instance 'JwtRep' Text UserName where
--  rep   = toText
--  unRep = Just . Un   
-- @
-- 
--   But there is an easier way. Just use /deriving/ clause
--
-- @
-- newtype UserName = Un { toText :: Text }
--  deriving stock (Show, Eq)
--  deriving newtype ('JwtRep' ByteString)
-- @
--
-- == JsonBuilder and lists
--
--  To encode values such as lists, a different strategy has to be used. 
--  Because JWT values have to be in JSON format and there is no native support for more complex data structures (such as JSON arrays)
--  we have to do the conversion ourselves. For this we must know how to encode the value as a __JSON value__
--
--  This is the role of 'JsonBuilder' typeclass.
--  You must provide its instance if you want to be able to __encode lists of values of a custom type__.
--
--  If you already have a 'JwtRep' instance, the default implementation (use 'JsonBuilder' of the 'rep') should be fine
--
-- @
-- instance 'JsonBuilder' UserName
-- @
-- 
--  or
--
-- @
-- newtype UserName = Un { toText :: Text }
--  deriving stock (Show, Eq)
--  deriving newtype ('JwtRep' ByteString, 'JsonBuilder')
-- @
--
-- = Decoding
--
--   The decoders are similarily divided into three groups:
--
--       * /Native/ - types: ByteString, Bool, Int, NumericDate and 'JsonByteString'.
--         Decoded in C
--       * /Derived/ - types for which a 'JwtRep' instance exists.
--         They are extracted via 'unRep' (transitively) from something we could decode
--       * /Specialized/ - Lists
--
-- == JwtRep typeclass
--
--   'JwtRep' also knows how to go backwards - from the JWT representation to, maybe, a value. To complete the 'UUID' example
--     
-- @
-- instance 'JwtRep' ByteString UUID where
--   rep = 'UUID.toASCIIBytes'
--   unRep = 'UUID.fromASCIIBytes'
-- @
--
--   /Derived/ decoder will first try to parse a byteString from JSON, and then convert it via 'unRep' to a UUID.
--   Each of these steps can fail - the failure will manifest itself as "Libjwt.Exceptions.MissingClaim" or
--   @Nothing@ if all you want is @Maybe UUID@
--
--   And of course, 'JwtRep' of @UserName@ handles decoding the same way as described.
--
-- == JsonParser and lists
--
--  'JsonParser' performs the opposite role of 'JsonBuilder' during decoding. It is used for extracting values
--  out of JSON arrays
--
--  You must provide its instance if you want to be able to __decode lists of values of a custom type__.
--
--  And again - the default implementation (@unRep <=< jsonParser@) should be fine
--
-- @
-- instance 'JsonParser' UserName
-- @
-- 
--  or
--
-- @
-- newtype UserName = Un { toText :: Text }
--  deriving stock (Show, Eq)
--  deriving newtype ('JwtRep' ByteString, 'JsonBuilder', 'JsonParser')
-- @
--
-- = Integration with aeson
--
--  If you want to work with more complex objects as claims (e.g. lists of records) or
--  you just want to integrate this library with your existing code that uses /aeson/ - it's simple
-- 
-- @
-- data Account = MkAccount { account_name :: Text, account_id :: UUID }
--   deriving stock (Show, Eq, Generic)
-- 
-- instance FromJSON Account
-- instance ToJSON Account
-- 
-- instance 'JwtRep' 'JsonByteString' Account where
--   rep   = Json . encode
--   unRep = decode . toJson
-- 
-- instance 'JsonBuilder' Account
-- instance 'JsonParser' Account
-- @
--
--  'JsonByteString' is for cases where you already have your claims correctly represented as JSON,
--  so you can use /aeson/ (or any other method) to create 'JsonByteString'.
--
-- = Warning
--
--  Do not use @\NUL@ characters in strings you encode or decode with this library.
--  Safety is not guaranteed (ie, may crash your program) due to the way /libjwt/ works.
module Libjwt.Classes
  ( JwtRep(..)
  , JsonBuilder(..)
  , JsonParser(..)
  , JsonToken(..)
  )
where

import           Libjwt.ASCII
import           Libjwt.FFI.Jwt                 ( JsonToken(..) )
import           Libjwt.Flag
import           Libjwt.JsonByteString
import           Libjwt.NumericDate

import           Control.Monad                  ( guard
                                                , (<=<)
                                                )
import           Control.Monad.Zip              ( mzip )

import           Data.ByteString                ( ByteString )
import qualified Data.ByteString               as Word8
import           Data.ByteString.Builder        ( Builder
                                                , char7
                                                , byteString
                                                , intDec
                                                , int64Dec
                                                , string7
                                                , charUtf8
                                                )
import           Data.ByteString.Builder.Extra  ( toLazyByteStringWith
                                                , safeStrategy
                                                )
import           Data.ByteString.Builder.Prim   ( (>*<)
                                                , condB
                                                , (>$<)
                                                , liftFixedToBounded
                                                )
import qualified Data.ByteString.Builder.Prim  as E
import qualified Data.ByteString.Char8         as Char8
import qualified Data.ByteString.Lazy          as Lazy
import qualified Data.ByteString.Lazy.Char8    as Lazy8

import qualified Data.ByteString.Lazy.UTF8     as LazyUTF8
import qualified Data.ByteString.UTF8          as UTF8

import           Data.Char                      ( ord
                                                , digitToInt
                                                , chr
                                                )
import           Data.Coerce                    ( coerce )

import           Data.Either.Extra              ( eitherToMaybe )

import           Data.List                      ( intersperse )
import           Data.List.NonEmpty             ( NonEmpty )
import qualified Data.List.NonEmpty            as NEL
import           Data.Maybe                     ( fromJust )

import           Data.Text                      ( Text )
import qualified Data.Text.Encoding            as Text
import           Data.Text.Lazy                 ( toStrict )
import qualified Data.Text.Lazy.Encoding       as LazyText

import           Data.Time.Calendar             ( Day )
import           Data.Time.Clock
import           Data.Time.Format.ISO8601
import           Data.Time.LocalTime

import           Data.UUID                      ( UUID )
import qualified Data.UUID                     as UUID

import           Data.Word                      ( Word16
                                                , Word8
                                                )

-- | Conversion between @a@ and @b@ 
--
--   If an instance of this typeclass exists for a type @b@, then JWT encoder and decoder can be derived for that type.
--   This derived encoder/decoder will use the encoder/decoder of @a@ and perform the convertions through this typeclass.
class JwtRep a b | b -> a where
  -- | Convert @b@ to @a@
  rep :: b -> a
  -- | Try to convert @a@ to @b@, returning @Nothing@ if unable
  unRep :: a -> Maybe b

instance JwtRep ByteString String where
  rep   = UTF8.fromString
  unRep = Just . UTF8.toString

instance JwtRep ByteString ASCII where
  rep   = Char8.pack . coerce
  unRep = coerce . Just . Char8.unpack

instance JwtRep ByteString UUID where
  rep   = UUID.toASCIIBytes
  unRep = UUID.fromASCIIBytes

encodeAsIso8601 :: (ISO8601 t) => t -> ASCII
encodeAsIso8601 = ASCII . iso8601Show

decodeFromISO8601 :: (ISO8601 t) => ASCII -> Maybe t
decodeFromISO8601 = iso8601ParseM . getASCII

instance JwtRep ASCII UTCTime where
  rep   = encodeAsIso8601
  unRep = decodeFromISO8601

instance JwtRep ASCII ZonedTime where
  rep   = encodeAsIso8601
  unRep = decodeFromISO8601

instance JwtRep ASCII LocalTime where
  rep   = encodeAsIso8601
  unRep = decodeFromISO8601

instance JwtRep ASCII Day where
  rep   = encodeAsIso8601
  unRep = decodeFromISO8601

instance JwtRep ByteString Text where
  rep   = Text.encodeUtf8
  unRep = eitherToMaybe . Text.decodeUtf8'

instance JwtRep [a] (NonEmpty a) where
  rep   = NEL.toList
  unRep = NEL.nonEmpty

instance AFlag a => JwtRep ASCII (Flag a) where
  rep   = getFlagValue
  unRep = setFlagValue

-- | Types that can be converted to a valid JSON representation
--
--   This typeclass will be used to encode a list of @t@ values (or a list of tuples whose element is of type @t@)
class JsonBuilder t where
  -- | Encode as JSON.
  -- 
  --   Must generate a valid JSON value: take care of quoting, escaping, UTF-8 encoding etc.
  jsonBuilder :: t -> Builder

  default jsonBuilder :: (JwtRep a t, JsonBuilder a) => t -> Builder
  jsonBuilder = jsonBuilder . rep

instance JsonBuilder ByteString where
  jsonBuilder = optimizedEscapeWords E.primMapByteStringBounded

instance JsonBuilder Bool where
  jsonBuilder True  = "true"
  jsonBuilder False = "false"

instance JsonBuilder Int where
  jsonBuilder = intDec

instance JsonBuilder NumericDate where
  jsonBuilder = int64Dec . coerce

instance {-# OVERLAPPING #-} JsonBuilder String where
  jsonBuilder = optimizedEscapeString E.charUtf8

instance JsonBuilder ASCII where
  jsonBuilder = optimizedEscapeString (liftFixedToBounded E.char7) . getASCII

instance JsonBuilder Text where
  jsonBuilder = optimizedEscapeWords Text.encodeUtf8BuilderEscaped

instance JsonBuilder UUID where
  jsonBuilder = quoteString . byteString . UUID.toASCIIBytes

iso8601Builder :: (ISO8601 t) => t -> Builder
iso8601Builder = quoteString . string7 . iso8601Show

instance JsonBuilder UTCTime where
  jsonBuilder = iso8601Builder

instance JsonBuilder LocalTime where
  jsonBuilder = iso8601Builder

instance JsonBuilder ZonedTime where
  jsonBuilder = iso8601Builder

instance JsonBuilder Day where
  jsonBuilder = iso8601Builder

instance AFlag a => JsonBuilder (Flag a) where
  jsonBuilder = quoteString . string7 . getASCII . getFlagValue

instance JsonBuilder JsonByteString where
  jsonBuilder = toJsonBuilder

instance JsonBuilder a => JsonBuilder [a] where
  jsonBuilder = encodeArray

instance JsonBuilder a => JsonBuilder (Maybe a) where
  jsonBuilder Nothing  = "null"
  jsonBuilder (Just a) = jsonBuilder a

instance (JsonBuilder a, JsonBuilder b) => JsonBuilder (a, b) where
  jsonBuilder (a, b) =
    arrayBrackets $ jsonBuilder a <> char7 ',' <> jsonBuilder b

encodeArray :: JsonBuilder a => [a] -> Builder
encodeArray =
  arrayBrackets . mconcat . intersperse (char7 ',') . map jsonBuilder

arrayBrackets :: Builder -> Builder
arrayBrackets bs = char7 '[' <> bs <> char7 ']'

quoteString :: Builder -> Builder
quoteString bs = char7 '"' <> bs <> char7 '"'

optimizedEscapeWords :: (E.BoundedPrim Word8 -> a -> Builder) -> a -> Builder
optimizedEscapeWords f = quoteString . f
  (   condB (== 92) (fixed2 ('\\', '\\'))
  $   condB (== 34) (fixed2 ('\\', '"'))
  $   condB (>= 32) (liftFixedToBounded E.word8)
  $   condB (== 13) (fixed2 ('\\', 'r'))
  $   condB (== 12) (fixed2 ('\\', 'f'))
  $   condB (== 10) (fixed2 ('\\', 'n'))
  $   condB (== 9)  (fixed2 ('\\', 't'))
  $   condB (== 8)  (fixed2 ('\\', 'b'))
  $   liftFixedToBounded
  $   fromIntegral
  >$< uEscape
  )

optimizedEscapeString :: E.BoundedPrim Char -> String -> Builder
optimizedEscapeString enc = quoteString . E.primMapListBounded escape
 where
  escape =
    condB (== '\\') (fixed2 ('\\', '\\'))
      $   condB (== '"')  (fixed2 ('\\', '"'))
      $   condB (>= ' ')  enc
      $   condB (== '\r') (fixed2 ('\\', 'r'))
      $   condB (== '\f') (fixed2 ('\\', 'f'))
      $   condB (== '\n') (fixed2 ('\\', 'n'))
      $   condB (== '\t') (fixed2 ('\\', 't'))
      $   condB (== '\b') (fixed2 ('\\', 'b'))
      $   liftFixedToBounded
      $   (fromIntegral . ord)
      >$< uEscape

-- | Types that can be converted from JSON representation
--
--   This typeclass will be used to decode a list of @a@ values (or a list of tuples whose element is of type @a@)
class JsonParser a where
  -- | Decode from JSON token.
  jsonParser :: JsonToken -> Maybe a

  default jsonParser :: (JwtRep t a, JsonParser t) => JsonToken -> Maybe a
  jsonParser = unRep <=< jsonParser

instance JsonParser ByteString where
  jsonParser (JsStr bs) = Just $ withUnescapedString Lazy.toStrict id bs
  jsonParser _          = Nothing

instance JsonParser Bool where
  jsonParser JsTrue  = Just True
  jsonParser JsFalse = Just False
  jsonParser _       = Nothing

instance JsonParser Int where
  jsonParser (JsNum bs) = do
    (int, remainder) <- Char8.readInt bs
    guard $ Char8.null remainder
    return int
  jsonParser _ = Nothing

instance {-# OVERLAPPING #-} JsonParser String where
  jsonParser (JsStr bs) =
    Just $ withUnescapedString LazyUTF8.toString UTF8.toString bs
  jsonParser _ = Nothing

instance JsonParser ASCII where
  jsonParser (JsStr bs) =
    Just $ coerce $ withUnescapedString Lazy8.unpack Char8.unpack bs
  jsonParser _ = Nothing

instance JsonParser Text where
  jsonParser (JsStr bs) = eitherToMaybe $ withUnescapedString
    (fmap toStrict . LazyText.decodeUtf8')
    Text.decodeUtf8'
    bs
  jsonParser _ = Nothing

instance JsonParser NumericDate where
  jsonParser (JsNum bs) = do
    (int, remainder) <- Char8.readInteger bs
    guard $ Char8.null remainder
    return $ NumericDate $ fromInteger int
  jsonParser _ = Nothing

instance JsonParser UUID where
  jsonParser (JsStr bs) = UUID.fromASCIIBytes bs
  jsonParser _          = Nothing

iso8601Parser :: ISO8601 t => JsonToken -> Maybe t
iso8601Parser (JsStr bs) = iso8601ParseM $ Char8.unpack bs
iso8601Parser _          = Nothing

instance JsonParser UTCTime where
  jsonParser = iso8601Parser

instance JsonParser LocalTime where
  jsonParser = iso8601Parser

instance JsonParser ZonedTime where
  jsonParser = iso8601Parser

instance JsonParser Day where
  jsonParser = iso8601Parser

instance AFlag a => JsonParser (Flag a) where
  jsonParser (JsStr bs) = setFlagValue $ ASCII $ Char8.unpack bs
  jsonParser _          = Nothing

instance JsonParser JsonByteString where
  jsonParser (JsBlob bs) = Just $ jsonFromStrict bs
  jsonParser _           = Nothing

instance JsonParser a => JsonParser [a] where
  jsonParser (JsArray as) = traverse jsonParser as
  jsonParser _            = Nothing

instance JsonParser a => JsonParser (Maybe a) where
  jsonParser JsNull = Just Nothing
  jsonParser a'     = Just <$> jsonParser a'

instance (JsonParser a, JsonParser b) => JsonParser (a, b) where
  jsonParser (JsArray [a', b']) = mzip (jsonParser a') (jsonParser b')
  jsonParser _                  = Nothing

withUnescapedString
  :: (Lazy.ByteString -> a) -> (ByteString -> a) -> ByteString -> a
withUnescapedString lazy strict bs = case Word8.break (== 92) bs of
  (x, y)
    | Word8.null y -> strict x
    | otherwise -> lazy
    $ toLazyByteStringWith allocationStrategy mempty (byteString x <> go0 y)
 where
  go0 ws = case fromJust $ Word8.uncons rest of
    (h, tl)
      | h == 117
      -> let (hex, tl') = Word8.splitAt 4 tl
         in  charUtf8 (chr $ hexValue hex) <> builder tl'
      | h == 116
      -> char7 '\t' <> builder tl
      | h == 114
      -> char7 '\r' <> builder tl
      | h == 110
      -> char7 '\n' <> builder tl
      | h == 102
      -> char7 '\f' <> builder tl
      | h == 98
      -> char7 '\b' <> builder tl
      | h == 92
      -> char7 '\\' <> builder tl
      | otherwise
      -> go1 rest
   where
    rest = Word8.tail ws
    builder b = case Word8.uncons b of
      Nothing -> mempty
      Just (h, _) | h == 92   -> go0 b
                  | otherwise -> go1 b

  go1 ws = case Word8.break (== 92) ws of
    (x, y) | Word8.null y -> byteString x
           | otherwise    -> byteString x <> go0 y

  allocationStrategy =
    let initialLength = Word8.length bs
        wanted        = min 32 $ (initialLength + 7) `div` 8 * 8
    in  safeStrategy wanted wanted

  hexValue = Char8.foldl' (\val c -> val * 16 + digitToInt c) 0

fixed2 :: (Char, Char) -> E.BoundedPrim b
fixed2 repl = liftFixedToBounded $ const repl >$< E.char7 >*< E.char7
{-# INLINE fixed2 #-}

uEscape :: E.FixedPrim Word16
uEscape = (('\\', 'u'), ) >$< (E.char7 >*< E.char7) >*< E.word16HexFixed
{-# INLINE uEscape #-}

