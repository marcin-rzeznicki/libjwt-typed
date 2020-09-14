{-# LANGUAGE GeneralizedNewtypeDeriving #-}
--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_GHC -Wno-unused-binds -Wno-missing-signatures #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

module Web.Libjwt.Tutorial
  ()
where

import           Web.Libjwt
import           Libjwt.Classes

import           Control.Arrow                  ( left )
import           Control.Exception              ( catch
                                                , displayException
                                                )
import           Data.ByteString                ( ByteString )
import           Data.Default
import           Data.Either.Validation         ( validationToEither )
import           Data.List.NonEmpty             ( NonEmpty(..) )
import           Data.Text                      ( Text )
import           Data.Time.Clock                ( UTCTime )
import           Data.UUID                      ( UUID )
import           GHC.Generics

import           Prelude                 hiding ( exp )


data UserClaims = UserClaims { userId :: UUID
                             , userName :: Text
                             , isRoot :: Bool
                             , createdAt :: UTCTime
                             , accounts :: NonEmpty UUID
                             }
  deriving stock (Eq, Show, Generic)

instance ToPrivateClaims UserClaims
instance FromPrivateClaims UserClaims

hmac512 :: Alg
hmac512 =
  HS512
    "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\
    \YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\
    \Y2IwMDZhYWY1MjY1OTQgIC0K"

mkPayload UserClaims {..} currentTime =
  let now = fromUTC currentTime
  in  def
        { iss           = Iss (Just "myApp")
        , aud           = Aud ["https://myApp.com"]
        , iat           = Iat (Just now)
        , exp           = Exp (Just $ now `plusSeconds` 300)
        , privateClaims = toPrivateClaims
                            ( #user_name ->> userName
                            , #is_root ->> isRoot
                            , #user_id ->> userId
                            , #created ->> createdAt
                            , #accounts ->> accounts
                            )
        }

mkPayload' UserClaims {..} = jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  ( #user_name ->> userName
  , #is_root ->> isRoot
  , #user_id ->> userId
  , #created ->> createdAt
  , #accounts ->> accounts
  )

mkPayload'' = jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  UserClaims { userId    = read "5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25"
             , userName  = "JohnDoe"
             , isRoot    = False
             , createdAt = read "2020-07-31 11:45:00 UTC"
             , accounts  = read "0bdf91cc-48bb-47f5-b633-920c34bd2352" :| []
             }

mkPayload''' =
  jwtPayload
      (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
    $ withNs
        (Ns @"https://myApp.com")
        UserClaims
          { userId    = read "5a7c5cdd-3909-456b-9dd2-6ba84bfeeb25"
          , userName  = "JohnDoe"
          , isRoot    = False
          , createdAt = read "2020-07-31 11:45:00 UTC"
          , accounts  = read "0bdf91cc-48bb-47f5-b633-920c34bd2352" :| []
          }

token :: IO ByteString
token = getToken . sign hmac512 <$> mkPayload''

type MyJwt
  = Jwt
      '["userId" ->> UUID, "userName" ->> Text, "isRoot" ->> Bool, "createdAt" ->> UTCTime, "accounts" ->> NonEmpty UUID]
      'NoNs

decodeDoNotUse :: IO (Decoded MyJwt)
decodeDoNotUse = decodeByteString hmac512 =<< token

decodeAndValidate :: IO (ValidationNEL ValidationFailure (Validated MyJwt))
decodeAndValidate = jwtFromByteString settings mempty hmac512 =<< token
  where settings = Settings { leeway = 5, appName = Just "https://myApp.com" }

decodeAndValidateFull :: IO (Either String UserClaims)
decodeAndValidateFull =
  (   left (("Token not valid: " ++) . show)
    .   fmap toUserClaims
    .   validationToEither
    <$> decodeAndValidate
    )
    `catch` onError
 where
  toUserClaims = fromPrivateClaims . privateClaims . payload . getValid
  onError (e :: SomeDecodeException) =
    return $ Left $ "Cannot decode token " ++ displayException e

-- Extending

newtype UserName = Un { toText :: Text }
  deriving stock (Show, Eq)
  deriving newtype (JwtRep ByteString)

instance JsonBuilder UserName
instance JsonParser UserName

token' :: IO ByteString
token' = getToken . sign hmac512 <$> jwtPayload
  (withIssuer "myApp" <> withRecipient "https://myApp.com" <> setTtl 300)
  ( #user_name ->> Un "John Doe"
  , #additional_names ->> [Un "Johnny Doe", Un "Doe"]
  )
