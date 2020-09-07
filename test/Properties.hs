{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}

module Properties
  ( spec
  )
where

import           Web.Libjwt
import           Generators
import           Libjwt.Classes
import           Libjwt.JsonByteString
import           Libjwt.JwtValidation           ( runValidation )
import           Libjwt.NumericDate             ( minusSeconds )

import           Control.Arrow                  ( left )
import           Control.Exception              ( displayException )

import           Control.Monad.Trans.Reader     ( runReader )

import           Data.Aeson                     ( FromJSON
                                                , ToJSON
                                                , encode
                                                , decode
                                                )

import           Data.Default

import           Data.Either.Validation        as V

import           Data.Functor                   ( (<&>) )
import           Data.List.NonEmpty             ( NonEmpty )

import           Data.Time.Calendar             ( Day )
import           Data.Time.Clock                ( UTCTime )

import           Data.UUID                      ( UUID )

import           GHC.Generics

import           Test.Hspec
import           Test.Hspec.QuickCheck          ( modifyArgs
                                                , prop
                                                )

import           Test.QuickCheck

import           Test.QuickCheck.Instances      ( )

import           Prelude                 hiding ( exp )

spec :: Spec
spec = modifyArgs quickcheckArgs $ do
  prop "enc-dec-roundtrip-reg-only" prop_encode_decode_roundtrip_reg_only
  prop "enc-dec-roundtrip"          prop_encode_decode_roundtrip
  prop "enc-dec-roundtrip-ns"       prop_encode_decode_roundtrip_ns
  prop "enc-dec-roundtrip-comp"     prop_encode_decode_rountrip_comp
  prop "enc-dec-roundtrip-aeson"    prop_encode_decode_roundtrip_aeson
  prop "from-to-generic"            prop_from_to_generic
  prop "validity"                   prop_validity
 where
  quickcheckArgs args = args { maxSuccess      = 4000
                             , maxDiscardRatio = 5
                             , maxSize         = maxSize args `div` 2
                             , maxShrinks      = 1000
                             }

prop_encode_decode_roundtrip_poly
  :: (Decode (PrivateClaims pc ns), Encode (PrivateClaims pc ns), Show a, Eq a)
  => (Jwt pc ns -> a)
  -> (a -> Jwt pc ns)
  -> a
  -> Property
prop_encode_decode_roundtrip_poly project embed a =
  let jwt = embed a
  in  left
          displayException
          (   decodeByteString (alg $ header jwt) (getToken $ signJwt jwt)
          <&> project
          .   getDecoded
          )
        === pure a

prop_encode_decode_roundtrip_reg_only :: Jwt Empty 'NoNs -> Property
prop_encode_decode_roundtrip_reg_only = prop_encode_decode_roundtrip_poly id id

prop_encode_decode_roundtrip
  :: Jwt
       '["intField" ->> Int, "dateField" ->> UTCTime, "textField" ->> JwtText, "optField" ->> Maybe JwtString, "arrayField" ->> [JwtText], "nonEmptyField" ->> NonEmpty ASCII]
       'NoNs
  -> Property
prop_encode_decode_roundtrip = prop_encode_decode_roundtrip_poly id id

prop_encode_decode_roundtrip_ns
  :: Jwt
       '["dayField" ->> Day, "arrayField" ->> [Int], "stringField" ->> JwtString]
       ( 'SomeNs "https://example.com")
  -> Property
prop_encode_decode_roundtrip_ns = prop_encode_decode_roundtrip_poly id id

prop_encode_decode_rountrip_comp
  :: Jwt
       '["user_name" ->> JwtText, "is_root" ->> Bool, "type" ->> Flag AccountType, "client_id" ->> UUID, "created" ->> UTCTime, "accounts" ->> NonEmpty (UUID, JwtText)]
       'NoNs
  -> Property
prop_encode_decode_rountrip_comp = prop_encode_decode_roundtrip_poly id id

data AccountType = Regular | Pro | Admin
  deriving stock (Show, Eq, Generic)

instance AFlag AccountType

instance Arbitrary AccountType where
  arbitrary = elements [Regular, Pro, Admin]

data ClaimObj = MkClaimObj { userName :: JwtText, isRoot :: Bool, clientId :: UUID, createdAt :: UTCTime }
  deriving stock (Show, Eq, Generic)

instance ToPrivateClaims ClaimObj
instance FromPrivateClaims ClaimObj

instance Arbitrary ClaimObj where
  arbitrary =
    MkClaimObj <$> arbitrary <*> arbitrary <*> arbitrary <*> arbitrary

  shrink MkClaimObj { userName, isRoot, clientId, createdAt } =
    MkClaimObj
      <$> shrink userName
      <*> pure isRoot
      <*> shrink clientId
      <*> shrink createdAt

prop_from_to_generic :: ClaimObj -> Property
prop_from_to_generic claimObj = forAllBlind genHeader $ \header ->
  prop_encode_decode_roundtrip_poly
    (fromPrivateClaims . privateClaims . payload)
    (\claimObj' -> Jwt
      { header
      , payload = def { privateClaims = toPrivateClaims claimObj' }
      }
    )
    claimObj

data Account = MkAccount { account_name :: JwtText, account_id :: UUID }
  deriving stock (Show, Eq, Generic)

instance FromJSON Account
instance ToJSON Account

instance JwtRep JsonByteString Account where
  rep   = Json . encode
  unRep = decode . toJson

instance JsonBuilder Account
instance JsonParser Account

instance Arbitrary Account where
  arbitrary = MkAccount <$> arbitrary <*> arbitrary
  shrink (MkAccount name id) = MkAccount <$> shrink name <*> shrink id

prop_encode_decode_roundtrip_aeson
  :: Jwt '["user_id" ->> Int, "accounts" ->> NonEmpty Account] 'NoNs
  -> Property
prop_encode_decode_roundtrip_aeson = prop_encode_decode_roundtrip_poly id id

prop_validity
  :: UTCTime -> ValidationSettings -> Payload Empty 'NoNs -> Property
prop_validity time settings@Settings { leeway, appName } payload@ClaimsSet { exp, nbf, aud = Aud rs }
  | now > validFrom && now < validTo && appropriate
  = label "valid" $ classify triviallyValid "trivial" $ success validate
  | otherwise
  = label "invalid" $ failure validate
 where
  now       = fromUTC time

  validFrom = case nbf of
    Nbf Nothing    -> minBound
    Nbf (Just sth) -> sth `minusSeconds` leeway
  validTo = case exp of
    Exp Nothing    -> maxBound
    Exp (Just sth) -> sth `plusSeconds` leeway

  appropriate    = null rs || maybe False (`elem` rs) appName

  triviallyValid = exp == Exp Nothing && nbf == Nbf Nothing && null rs

  validate       = runReader (runValidation settings mempty payload) time

  success (V.Success _) = property True
  success errors        = counterexample (show errors) False

  failure (V.Failure _) = property True
  failure other         = counterexample (show other) False


