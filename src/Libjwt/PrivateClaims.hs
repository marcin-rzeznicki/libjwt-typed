--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE ViewPatterns #-}

module Libjwt.PrivateClaims
  ( Claim(..)
  , type (->>)
  , (->>)
  , GrantWitness
  , testify
  , GrantName(..)
  , grantNameVal
  , PrivateClaims
  , pattern (:<)
  , type Empty
  , nullClaims
  , CanAdd
  , addGrant
  , (.:)
  , CanGet
  , LookupClaimType
  , getGrant
  , (.!)
  , Namespace(..)
  , KnownNamespace(..)
  , Ns(..)
  , withNs
  , someNs
  , noNs
  , ToPrivateClaims(..)
  , FromPrivateClaims(..)
  )
where

import           Libjwt.Encoding
import           Libjwt.Decoding
import           Libjwt.FFI.Jwt (JwtT)

import           Control.Applicative            ( liftA2 )
import           Data.Coerce

import           Data.Default

import           Data.HashMap.Lazy              ( HashMap
                                                , (!)
                                                )
import qualified Data.HashMap.Lazy             as HashMap

import           Data.Kind

import           Data.Proxied                   ( selNameProxied )

import           Data.Proxy

import           GHC.Generics
import           GHC.OverloadedLabels
import           GHC.Show
import           GHC.TypeLits
import           Unsafe.Coerce                  ( unsafeCoerce )

infix 6 ->>
infixr 5 .:
infixr 5 :<

data Claim (a :: Type) = Grant Symbol a

type name ->> a = 'Grant name a

data Namespace = NoNs | SomeNs Symbol

class KnownNamespace (ns :: Namespace) where
  namespaceValue :: proxy ns -> Maybe String

instance KnownNamespace 'NoNs where
  namespaceValue _ = Nothing

instance KnownSymbol ns => KnownNamespace ('SomeNs ns) where
  namespaceValue _ = Just $ symbolVal (Proxy :: Proxy ns)

fullClaimName :: (KnownNamespace ns) => proxy ns -> String -> String
fullClaimName p claimName =
  maybe claimName (++ '/' : claimName) $ namespaceValue p
{-# INLINE fullClaimName #-}

fullClaimName' :: forall ns name . (KnownNamespace ns, KnownSymbol name) => String
fullClaimName' = fullClaimName (Proxy :: Proxy ns) $ symbolVal (Proxy :: Proxy name)

data Ns (ns :: Symbol) = Ns

instance (name ~ name') => IsLabel name (Ns name') where
  fromLabel = Ns

data Any = forall a . Any a
newtype PrivateClaims (ts :: [Claim Type]) (ns :: Namespace) = PrivateClaims { unsafeClaimsMap :: HashMap String Any }

type Empty = ('[] :: [Claim Type])

nullClaims :: PrivateClaims Empty 'NoNs
nullClaims = PrivateClaims HashMap.empty

data GrantName (name :: Symbol) = GrantName

instance (name ~ name') => IsLabel name (GrantName name') where
  fromLabel = GrantName

grantNameVal :: forall name . KnownSymbol name => GrantName name -> String
grantNameVal _ = symbolVal (Proxy :: Proxy name)

newtype GrantWitness (name :: Symbol) a = Witness { testify :: a }

(->>) :: GrantName name -> a -> GrantWitness name a
_ ->> a = Witness a

type family UniqueName (name :: Symbol) (ts :: [Claim Type]) :: Bool where
  UniqueName _ '[]           = 'True
  UniqueName n (n ->> _ : _) = 'False
  UniqueName n (_ : rest)    = UniqueName n rest

type family RequireUniqueName (isUnique :: Bool) (name :: Symbol) :: Constraint where
  RequireUniqueName 'True  _  = ()
  RequireUniqueName 'False n  = TypeError ('Text "Grant " ':<>: 'ShowType n ':<>: 'Text " is not unique in this claim set")

type family RestrictedName (name :: Symbol) :: Bool where
  RestrictedName "iss" = 'True
  RestrictedName "sub" = 'True
  RestrictedName "aud" = 'True
  RestrictedName "exp" = 'True
  RestrictedName "nbf" = 'True
  RestrictedName "iat" = 'True
  RestrictedName "jti" = 'True
  RestrictedName _     = 'False

type family DisallowRestrictedName (isRestricted :: Bool) (name :: Symbol) :: Constraint where
  DisallowRestrictedName 'False _ = ()
  DisallowRestrictedName 'True  n = TypeError
    ( 'ShowType n
      ':<>:
      'Text " is the name of the registered claim (it is exposed as a field that must be set directly or use JwtBuilder)"
    )

type family CanAdd n ns :: Constraint where
  CanAdd n ns = (KnownSymbol n, DisallowRestrictedName (RestrictedName n) n, RequireUniqueName (UniqueName n ns) n)

addGrant
  :: forall name a ts ns
   . CanAdd name ts
  => GrantName name
  -> a
  -> PrivateClaims ts ns
  -> PrivateClaims (name ->> a : ts) ns
addGrant _ a (PrivateClaims store) = PrivateClaims
  $ HashMap.insert claimName (Any a) store
  where claimName = symbolVal (Proxy :: Proxy name)

(.:) :: forall name a ts ns
      . CanAdd name ts
     => GrantWitness name a
     -> PrivateClaims ts ns
     -> PrivateClaims (name ->> a : ts) ns
(Witness a) .: pc = addGrant GrantName a pc

type family NameExists (name :: Symbol) (ts :: [Claim Type]) :: Bool where
  NameExists _ '[]           = 'False
  NameExists n (n ->> _ : _) = 'True
  NameExists n (_ : rest )   = NameExists n rest

type family RequireExists (exists :: Bool) (name :: Symbol) :: Constraint where
  RequireExists 'True  _ = ()
  RequireExists 'False n = TypeError ('Text "Grant " ':<>: 'ShowType n ':<>: 'Text " does not exist in this claim set")

type family CanGet n ns :: Constraint where
  CanGet n ns = (KnownSymbol n, RequireExists (NameExists n ns) n)

type family LookupClaimType (name :: Symbol) (ts :: [Claim Type]) :: Type where
  LookupClaimType n (n ->> a : _) = a
  LookupClaimType n (_ : rest)    = LookupClaimType n rest

unsafeLookup :: String -> PrivateClaims ts ns -> p
unsafeLookup claimName pc = unAny $ unsafeClaimsMap pc ! claimName
  where
    unAny (Any a) = unsafeCoerce a

getGrant
  :: forall name ts ns
   . CanGet name ts
  => GrantName name
  -> PrivateClaims ts ns
  -> LookupClaimType name ts
getGrant _ = unsafeLookup claimName
 where
  claimName = symbolVal (Proxy :: Proxy name)
{-# INLINE getGrant #-}

(.!) :: forall name ts ns
      . CanGet name ts
     => PrivateClaims ts ns
     -> GrantName name
     -> LookupClaimType name ts
pc .! name = getGrant name pc

getHead
  :: forall name a tl ns . (KnownSymbol name, KnownNamespace ns) => PrivateClaims (name ->> a : tl) ns -> (String, a)
getHead pc = (fullClaimName (Proxy :: Proxy ns) claimName, claimValue)
 where
  claimName = symbolVal (Proxy :: Proxy name)
  claimValue = unsafeLookup claimName pc
{-# INLINE getHead #-}

getTail :: PrivateClaims (name ->> a : tl) ns -> PrivateClaims tl ns
getTail = coerce

view :: forall name a tl ns . KnownSymbol name => PrivateClaims (name ->> a : tl) ns -> (a, PrivateClaims tl ns)
view pc = (a, tl)
 where
   a = pc .! (GrantName @name)
   tl = getTail pc

pattern (:<) :: KnownSymbol name => a -> PrivateClaims tl ns -> PrivateClaims (name ->> a : tl) ns
pattern head :< tail <- (view -> (head, tail))

{-# COMPLETE (:<) :: PrivateClaims #-}

withNs
  :: ToPrivateClaims a => Ns ns -> a -> PrivateClaims (Grants a) ( 'SomeNs ns)
withNs _ = coerce . toPrivateClaims

someNs :: Ns ns -> PrivateClaims ts 'NoNs -> PrivateClaims ts ( 'SomeNs ns)
someNs _ = coerce

noNs :: PrivateClaims ts any -> PrivateClaims ts 'NoNs
noNs = coerce

instance (ts ~ Empty, ns ~ 'NoNs) => Default (PrivateClaims ts ns) where
  def = nullClaims

instance Encode (PrivateClaims Empty ns) where
  encode _ = nullEncode

instance
  ( ClaimEncoder a
  , KnownSymbol name
  , KnownNamespace ns
  , Encode (PrivateClaims tl ns)
  )
  => Encode (PrivateClaims (name ->> a : tl) ns) where
  encode pc jwt = encodeClaim claimName a jwt >> encode (getTail pc) jwt
   where (claimName, a) = getHead pc

instance Decode (PrivateClaims Empty ns) where
  decode = const $ return $ coerce nullClaims

instance
  ( ty ~ DecodeAuxDef a
  , DecodeAux ty ns name a
  , CanAdd name tl
  , Decode (PrivateClaims tl ns)
  )
  => Decode (PrivateClaims (name ->> a : tl) ns) where
  decode jwt = liftA2 (.:) decodeHead decodeTail
    where
      decodeHead = decodeAux @ty @ns @name jwt
      decodeTail = decode jwt

data DecodeTy = Opt | Req | Mono

class DecodeAux (ty :: DecodeTy) (ns :: Namespace) (name :: Symbol) (a :: Type) where
  decodeAux :: JwtT -> JwtIO (GrantWitness name a)

instance
  ( b ~ Maybe a
  , Decodable a
  , KnownNamespace ns
  , KnownSymbol name
  )
  => DecodeAux 'Opt ns name b where
  decodeAux = coerce . getOptional . decodeClaimProxied (fullClaimName' @ns @name) (Proxy :: Proxy a)

instance
  ( Decodable a
  , KnownNamespace ns
  , KnownSymbol name
  )
  => DecodeAux 'Req ns name a where
  decodeAux = coerce . decodeClaimOrThrow (fullClaimName' @ns @name) (Proxy :: Proxy a)

instance
  ( b ~ [a]
  , Decodable [a]
  , KnownNamespace ns
  , KnownSymbol name
  )
  => DecodeAux 'Mono ns name b where
  decodeAux = coerce . getOrEmpty . decodeClaimProxied (fullClaimName' @ns @name) (Proxy :: Proxy b)

type family DecodeAuxDef a :: DecodeTy where
  DecodeAuxDef (Maybe b) = 'Opt
  DecodeAuxDef String    = 'Req
  DecodeAuxDef [b]       = 'Mono
  DecodeAuxDef _         = 'Req

type family Showable pc :: Constraint where
  Showable (PrivateClaims (name ->> a : tl) ns) = (KnownSymbol name, KnownNamespace ns, Show a, ShowL (PrivateClaims tl ns))

instance Show (PrivateClaims Empty ns) where
  show _ = "()"

instance Showable (PrivateClaims (name ->> a : tl) ns) => Show (PrivateClaims (name ->> a : tl) ns) where
  showsPrec _ pc =
    showChar '(' . showHead pc . showl (getTail pc) . showChar ')'

showHead
  :: (KnownSymbol name, KnownNamespace ns, Show a) => PrivateClaims ((name ->> a) : tl) ns -> ShowS
showHead pc =
  showChar '#' . showString claimName . showString " ->> " . showsPrec 6 a
  where (claimName, a) = getHead pc

class ShowL a where
  showl :: a -> ShowS

instance ShowL (PrivateClaims Empty ns) where
  showl _ = id

instance Showable (PrivateClaims (name ->> a : tl) ns) => ShowL (PrivateClaims (name ->> a : tl) ns) where
  showl pc = showCommaSpace . showHead pc . showl (getTail pc)

instance Eq (PrivateClaims Empty any) where
  _ == _ = True

instance (Eq a, KnownSymbol name, Eq (PrivateClaims tl ns)) => Eq (PrivateClaims (name ->> a : tl) ns) where
  pc1 == pc2 = pc1 .! (GrantName @name) == pc2 .! (GrantName @name) && getTail pc1 == getTail pc2

class ToPrivateClaims a where
  type Grants a :: [Claim Type]
  type Grants a = GrantsFromRecord (Rep a)

  type OutNs a :: Namespace
  type OutNs a = 'NoNs

  toPrivateClaims :: a -> PrivateClaims (Grants a) (OutNs a)

  default toPrivateClaims
    :: ( Generic a
       , RecordToPrivateClaims (Rep a)
       , Grants a ~ GrantsFromRecord (Rep a)
       , OutNs a ~ 'NoNs
       )
    => a -> PrivateClaims (Grants a) (OutNs a)
  toPrivateClaims = genericToPrivateClaims . from

class FromPrivateClaims a where
  fromPrivateClaims :: ts ~ Grants a => PrivateClaims ts ns -> a

  default fromPrivateClaims 
    :: ( Generic a
       , RecordFromPrivateClaims (Rep a)
       , ts ~ GrantsFromRecord(Rep a)
       ) 
    => PrivateClaims ts ns -> a
  fromPrivateClaims = to . genericFromPrivateClaims

class RecordToPrivateClaims g where
  type GrantsFromRecord g :: [Claim Type]

  genericToPrivateClaims :: g p -> PrivateClaims (GrantsFromRecord g) 'NoNs

class RecordFromPrivateClaims g where
  genericFromPrivateClaims :: PrivateClaims (GrantsFromRecord g) ns -> g p

instance RecordToPrivateClaims c => RecordToPrivateClaims (D1 m c) where
  type GrantsFromRecord (D1 m c) = GrantsFromRecord c

  genericToPrivateClaims (M1 c) = genericToPrivateClaims c

instance RecordFromPrivateClaims c => RecordFromPrivateClaims (D1 m c) where
  genericFromPrivateClaims = M1 . genericFromPrivateClaims

instance RecordToPrivateClaims f => RecordToPrivateClaims (C1 m f) where
  type GrantsFromRecord (C1 m f) = GrantsFromRecord f

  genericToPrivateClaims (M1 f) = genericToPrivateClaims f

instance RecordFromPrivateClaims f => RecordFromPrivateClaims (C1 m f) where
  genericFromPrivateClaims = M1 . genericFromPrivateClaims 

type family (+++) (lhs :: [k]) (rhs :: [k]) :: [k] where
  '[]        +++ rhs = rhs
  (a : rest) +++ rhs = a : (rest +++ rhs)

instance (RecordToPrivateClaims s1, RecordToPrivateClaims s2) => RecordToPrivateClaims (s1 :*: s2) where
  type GrantsFromRecord (s1 :*: s2) = GrantsFromRecord s1 +++ GrantsFromRecord s2

  genericToPrivateClaims (s1 :*: s2) = PrivateClaims $ HashMap.union store1 store2
    where
      store1 = unsafeClaimsMap $ genericToPrivateClaims s1
      store2 = unsafeClaimsMap $ genericToPrivateClaims s2

instance (RecordFromPrivateClaims s1, RecordFromPrivateClaims s2) => RecordFromPrivateClaims (s1 :*: s2) where
  genericFromPrivateClaims pc = s1 :*: s2 where
    s1 = genericFromPrivateClaims (coerce pc)
    s2 = genericFromPrivateClaims (coerce pc)

type family HasSelectorName (m :: Meta) :: Constraint where
  HasSelectorName ('MetaSel ('Just s) _ _ _) = ()
  HasSelectorName _ = TypeError
    ( 'Text "Only records with named fields can be converted to PrivateClaims. For instance, "
      ':$$:
      'Text "data Good = MkGood { a :: Int, b :: String } is ok, but "
      ':$$:
      'Text "data Bad = MkBad Int String is not"
    )

type family SelectorName (m :: Meta) :: Symbol where
  SelectorName ('MetaSel ('Just s) _ _ _) = s

instance (Selector s, HasSelectorName s) =>  RecordToPrivateClaims (S1 s (Rec0 a)) where
  type GrantsFromRecord (S1 s (Rec0 a)) = '[SelectorName s ->> a]

  genericToPrivateClaims (M1 (K1 a)) = PrivateClaims $ HashMap.singleton fieldName $ Any a
    where
      fieldName = selNameProxied (Proxy :: Proxy (S1 s (Rec0 a) p))

instance (Selector s, HasSelectorName s) => RecordFromPrivateClaims (S1 s (Rec0 a)) where
  genericFromPrivateClaims = M1 . K1 . unsafeLookup fieldName
    where
      fieldName = selNameProxied (Proxy :: Proxy (S1 s (Rec0 a) p))

instance
  ( TypeError
    ( 'Text "Only records with named fields can be converted to PrivateClaims. For instance, "
      ':$$:
      'Text "data Good = MkGood { a :: Int, b :: String } is ok, but "
      ':$$:
      'Text "data Bad = Bad1 Int | Bad2 String is not"
    )
  )
  => RecordToPrivateClaims (any :+: thing) where
    genericToPrivateClaims = error "impossible"

instance
  ( TypeError
    ( 'Text "Only records with named fields can be constructed from PrivateClaims. For instance, "
      ':$$:
      'Text "data Good = MkGood { a :: Int, b :: String } is ok, but "
      ':$$:
      'Text "data Bad = Bad1 Int | Bad2 String is not"
    )
  )
  => RecordFromPrivateClaims (any :+: thing) where
  genericFromPrivateClaims = error "impossible"

instance ToPrivateClaims () where
  type Grants () = Empty

  toPrivateClaims _ = nullClaims

instance CanAdd n '[] => ToPrivateClaims (GrantWitness n a) where
  type Grants (GrantWitness n a) = '[n ->> a]
  toPrivateClaims (Witness a) = addGrant GrantName a nullClaims

instance (CanAdd n2 '[], CanAdd n1 '[n2 ->> b]) => ToPrivateClaims (GrantWitness n1 a, GrantWitness n2 b) where
  type Grants (GrantWitness n1 a, GrantWitness n2 b) = '[n1 ->> a, n2 ->> b]
  toPrivateClaims (Witness a, Witness b) =
    addGrant GrantName a $ addGrant GrantName b nullClaims

instance (KnownSymbol n1, KnownSymbol n2) => FromPrivateClaims (GrantWitness n1 a, GrantWitness n2 b) where
  fromPrivateClaims (a :< b :< _) = (Witness a, Witness b)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c]
  , CanAdd n2 '[n3 ->> c]
  , CanAdd n3 '[]
  )
  => ToPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c) where
  type Grants (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c) = '[n1 ->> a, n2 ->> b, n3 ->> c]
  toPrivateClaims (Witness a, Witness b, Witness c) =
    addGrant GrantName a $
    addGrant GrantName b $
    addGrant GrantName c nullClaims

instance 
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  ) => FromPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c) where
  fromPrivateClaims (a :< b :< c :< _) = (Witness a, Witness b ,Witness c)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d]
  , CanAdd n2 '[n3 ->> c, n4 ->> d]
  , CanAdd n3 '[n4 ->> d]
  , CanAdd n4 '[]
  )
  => ToPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c, GrantWitness n4 d) where
  type Grants (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c, GrantWitness n4 d) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d]
  toPrivateClaims (Witness a, Witness b, Witness c, Witness d) =
    addGrant GrantName a $
    addGrant GrantName b $
    addGrant GrantName c $
    addGrant GrantName d nullClaims

instance 
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  ) 
  => FromPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c, GrantWitness n4 d) where
  fromPrivateClaims (a :< b :< c :< d :< _) =
    (Witness a, Witness b, Witness c, Witness d)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e]
  , CanAdd n2 '[n3 ->> c, n4 ->> d, n5 ->> e]
  , CanAdd n3 '[n4 ->> d, n5 ->> e]
  , CanAdd n4 '[n5 ->> e]
  , CanAdd n5 '[]
  )
  => ToPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c, GrantWitness n4 d, GrantWitness n5 e) where
  type Grants
    ( GrantWitness n1 a
    , GrantWitness n2 b
    , GrantWitness n3 c
    , GrantWitness n4 d
    , GrantWitness n5 e) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e) =
    addGrant GrantName a $
    addGrant GrantName b $
    addGrant GrantName c $
    addGrant GrantName d $
    addGrant GrantName e nullClaims

instance
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  , KnownSymbol n5
  )
  => FromPrivateClaims (GrantWitness n1 a, GrantWitness n2 b, GrantWitness n3 c, GrantWitness n4 d, GrantWitness n5 e) where
  fromPrivateClaims (a :< b :< c :< d :< e :< _) = (Witness a, Witness b, Witness c, Witness d, Witness e)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f]
  , CanAdd n2 '[n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f]
  , CanAdd n3 '[n4 ->> d, n5 ->> e, n6 ->> f]
  , CanAdd n4 '[n5 ->> e, n6 ->> f]
  , CanAdd n5 '[n6 ->> f]
  , CanAdd n6 '[]
  )
  => ToPrivateClaims
     ( GrantWitness n1 a
     , GrantWitness n2 b
     , GrantWitness n3 c
     , GrantWitness n4 d
     , GrantWitness n5 e
     , GrantWitness n6 f) where
  type Grants
    ( GrantWitness n1 a
    , GrantWitness n2 b
    , GrantWitness n3 c
    , GrantWitness n4 d
    , GrantWitness n5 e
    , GrantWitness n6 f) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f) =
    addGrant GrantName a $
    addGrant GrantName b $
    addGrant GrantName c $
    addGrant GrantName d $
    addGrant GrantName e $
    addGrant GrantName f nullClaims

instance   
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  , KnownSymbol n5
  , KnownSymbol n6
  )
  =>  FromPrivateClaims
      ( GrantWitness n1 a
      , GrantWitness n2 b
      , GrantWitness n3 c
      , GrantWitness n4 d
      , GrantWitness n5 e
      , GrantWitness n6 f) where
  fromPrivateClaims (a :< b :< c :< d :< e :< f :< _) =
    (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f, n7 ->> g]
  , CanAdd n2 '[n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f, n7 ->> g]
  , CanAdd n3 '[n4 ->> d, n5 ->> e, n6 ->> f, n7 ->> g]
  , CanAdd n4 '[n5 ->> e, n6 ->> f, n7 ->> g]
  , CanAdd n5 '[n6 ->> f, n7 ->> g]
  , CanAdd n6 '[n7 ->> g]
  , CanAdd n7 '[]
  )
  => ToPrivateClaims
    ( GrantWitness n1 a
    , GrantWitness n2 b
    , GrantWitness n3 c
    , GrantWitness n4 d
    , GrantWitness n5 e
    , GrantWitness n6 f
    , GrantWitness n7 g) where
  type Grants
    ( GrantWitness n1 a
    , GrantWitness n2 b
    , GrantWitness n3 c
    , GrantWitness n4 d
    , GrantWitness n5 e
    , GrantWitness n6 f
    , GrantWitness n7 g) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f, n7 ->> g]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f, Witness g) =
    addGrant GrantName a $
    addGrant GrantName b $
    addGrant GrantName c $
    addGrant GrantName d $
    addGrant GrantName e $
    addGrant GrantName f $
    addGrant GrantName g nullClaims

instance
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  , KnownSymbol n5
  , KnownSymbol n6
  , KnownSymbol n7
  ) 
  => FromPrivateClaims 
     ( GrantWitness n1 a
     , GrantWitness n2 b
     , GrantWitness n3 c
     , GrantWitness n4 d
     , GrantWitness n5 e
     , GrantWitness n6 f
     , GrantWitness n7 g) where
  fromPrivateClaims (a :< b :< c :< d :< e :< f :< g :< _) =
    (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f, Witness g)
   

instance ToPrivateClaims (PrivateClaims ts ns) where
  type Grants (PrivateClaims ts ns) = ts
  type OutNs (PrivateClaims ts ns) = ns
  toPrivateClaims = id

