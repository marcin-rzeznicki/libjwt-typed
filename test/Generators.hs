{-# OPTIONS_GHC -fno-warn-orphans #-}

{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

module Generators
  ( JwtString(..)
  , JwtText(..)
  , genHeader
  , genJwt
  , shrinkJwt
  )
where

import           Web.Libjwt
import qualified Env                           as E
import           Libjwt.Classes
import           Libjwt.NumericDate             ( toPOSIX )

import           Control.Applicative            ( liftA2 )

import           Data.Aeson                     ( FromJSON
                                                , ToJSON
                                                )

import           Data.ByteString                ( ByteString )

import           Data.Coerce

import           Data.Text                      ( Text )
import qualified Data.Text                     as T

import           Data.UUID                      ( UUID )

import           Test.QuickCheck

import           Test.QuickCheck.Instances      ( )

import           Prelude                 hiding ( exp )


instance Arbitrary Iss where
  arbitrary = genIss
  shrink    = shrinkIss

genIss :: Gen Iss
genIss = coerce genMaybeShortPrintable

shrinkIss :: Iss -> [Iss]
shrinkIss (Iss x) = coerce $ shrink x

instance Arbitrary Sub where
  arbitrary = genSub
  shrink    = shrinkSub

genSub :: Gen Sub
genSub = coerce genMaybeShortPrintable

shrinkSub :: Sub -> [Sub]
shrinkSub (Sub x) = coerce $ shrink x

instance Arbitrary Jti where
  arbitrary = genJti

genJti :: Gen Jti
genJti = coerce $ arbitrary @(Maybe UUID)

instance Arbitrary NumericDate where
  arbitrary = genNumericDate
  shrink    = shrinkNumericDate

genNumericDate :: Gen NumericDate
genNumericDate = fromPOSIX <$> arbitrary `suchThat` (>= 0)

shrinkNumericDate :: NumericDate -> [NumericDate]
shrinkNumericDate = shrinkMap fromPOSIX toPOSIX

instance Arbitrary Exp where
  arbitrary = genExp
  shrink    = shrinkExp

genExp :: Gen Exp
genExp = coerce $ arbitrary @(Maybe NumericDate)

shrinkExp :: Exp -> [Exp]
shrinkExp (Exp x) = coerce $ shrink x

instance Arbitrary Nbf where
  arbitrary = genNbf
  shrink    = shrinkNbf

genNbf :: Gen Nbf
genNbf = coerce $ arbitrary @(Maybe NumericDate)

shrinkNbf :: Nbf -> [Nbf]
shrinkNbf (Nbf x) = coerce $ shrink x

instance Arbitrary Iat where
  arbitrary = genIat
  shrink    = shrinkIat

genIat :: Gen Iat
genIat = coerce $ arbitrary @(Maybe NumericDate)

shrinkIat :: Iat -> [Iat]
shrinkIat (Iat x) = coerce $ shrink x

instance Arbitrary Aud where
  arbitrary = genAud
  shrink    = shrinkAud

genAud :: Gen Aud
genAud =
  coerce $ frequency [(8, pure []), (2, resize 5 $ listOf genShortPrintable)]

shrinkAud :: Aud -> [Aud]
shrinkAud (Aud aud) = coerce $ shrink aud

instance Arbitrary ASCII where
  arbitrary = genASCII
  shrink    = shrinkASCII

genASCII :: Gen ASCII
genASCII = coerce $ listOf $ arbitraryASCIIChar `suchThat` (/= '\NUL')

shrinkASCII :: ASCII -> [ASCII]
shrinkASCII = coerce . filter (notElem '\NUL') . shrink . getASCII

instance Arbitrary a => Arbitrary (Flag a) where
  arbitrary = coerce $ arbitrary @a

instance Arbitrary Alg where
  arbitrary = genAlg

genAlg :: Gen Alg
genAlg = elements [hs256, hs512, rs256, rs512, es256, es384, es512, None]
 where
  hs256 =
    HS256
      "MWNmYzExODA5OWFjOGM3NDNmMmM5Zjg5ZDc0YTM3M2VhMGNkMzA2MDY3ZjFhZDk5N2I3OTc5Yjdm\
      \NDg3NDBkMiAgLQo"
  hs512 =
    HS512
      "MjZkMDY2OWFiZmRjYTk5YjczZWFiZjYzMmRjMzU5NDYyMjMxODBjMTg3ZmY5OTZjM2NhM2NhN2Mx\
      \YzFiNDNlYjc4NTE1MjQxZGI0OWM1ZWI2ZDUyZmMzZDlhMmFiNjc5OWJlZTUxNjE2ZDRlYTNkYjU5\
      \Y2IwMDZhYWY1MjY1OTQgIC0K"
  rs256 = RS256 E.testRsa2048KeyPair
  rs512 = RS512 E.testRsa2048KeyPair
  es256 = ES256 E.testEcP256KeyPair
  es384 = ES384 E.testEcP384KeyPair
  es512 = ES512 E.testEcP521KeyPair

instance Arbitrary ValidationSettings where
  arbitrary = Settings <$> genLeeway <*> arbitrary
    where genLeeway = arbitrary `suchThat` (>= 0)
  shrink Settings { leeway, appName } =
    Settings <$> shrinkLeeway leeway <*> shrink appName
    where shrinkLeeway = filter (>= 0) . shrink

newtype JwtString = S { correctJwtString :: String }
  deriving newtype (JwtRep ByteString, Show, Eq)

correctJwtChar :: Char -> Bool
correctJwtChar '\NUL'   = False
correctJwtChar '\65534' = False
correctJwtChar '\65535' = False
correctJwtChar _        = True

instance Arbitrary JwtString where
  arbitrary = coerce $ listOf $ arbitrary `suchThat` correctJwtChar
  shrink    = coerce . filter (all correctJwtChar) . shrink . correctJwtString

newtype JwtText = T { correctJwtText :: Text }
  deriving newtype (JwtRep ByteString, Show, Eq, JsonBuilder, JsonParser, FromJSON, ToJSON)

instance Arbitrary JwtText where
  arbitrary = coerce $ T.pack . correctJwtString <$> arbitrary
  shrink =
    shrinkMap (T . T.pack . correctJwtString) $ S . T.unpack . correctJwtText

instance Arbitrary Header where
  arbitrary = genHeader

genHeader :: Gen Header
genHeader = Header <$> genAlg <*> pure JWT

instance Arbitrary (PrivateClaims ts ns) => Arbitrary (Jwt ts ns) where
  arbitrary = genJwt
  shrink    = shrinkJwt

genJwt :: Arbitrary (PrivateClaims ts ns) => Gen (Jwt ts ns)
genJwt = Jwt <$> genHeader <*> arbitrary

shrinkJwt :: Arbitrary (PrivateClaims pc ns) => Jwt pc ns -> [Jwt pc ns]
shrinkJwt jwt = shrinkMap (\payload' -> jwt { payload = payload' }) payload jwt

instance Arbitrary (PrivateClaims ts ns) => Arbitrary (Payload ts ns) where
  arbitrary =
    ClaimsSet
      <$> genIss
      <*> genSub
      <*> genAud
      <*> genExp
      <*> genNbf
      <*> genIat
      <*> genJti
      <*> arbitrary

  shrink ClaimsSet { iss, sub, aud, exp, nbf, iat, jti, privateClaims } =
    tail
      $   ClaimsSet
      <$> shrink' iss
      <*> shrink' sub
      <*> shrink' aud
      <*> shrink' exp
      <*> shrink' nbf
      <*> shrink' iat
      <*> shrink' jti
      <*> shrink' privateClaims
    where shrink' x = x : shrink x

instance Arbitrary (PrivateClaims Empty 'NoNs) where
  arbitrary = pure nullClaims

instance
  ( Arbitrary a
  , CanAdd n tl
  , Arbitrary (PrivateClaims tl 'NoNs)
  )
  => Arbitrary (PrivateClaims (n ->> a ': tl) 'NoNs) where
  arbitrary = liftA2 (.:) genWitness arbitrary
  shrink (a :< tl) = tail
    $ liftA2 (.:) (map (GrantName ->>) $ shrink' a) (shrink' tl)
    where shrink' x = x : shrink x

instance Arbitrary (PrivateClaims ts 'NoNs) => Arbitrary (PrivateClaims ts ('SomeNs ns)) where
  arbitrary = someNs Ns <$> arbitrary
  shrink    = shrinkMap (someNs Ns) noNs

genWitness :: Arbitrary a => Gen (GrantWitness name a)
genWitness = (GrantName ->>) <$> arbitrary

genShortPrintable :: Gen PrintableString
genShortPrintable = resize 32 arbitrary

genMaybeShortPrintable :: Gen (Maybe PrintableString)
genMaybeShortPrintable = liftArbitrary genShortPrintable

