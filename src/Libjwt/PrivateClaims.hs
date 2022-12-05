--   This Source Code Form is subject to the terms of the Mozilla Public
--   License, v. 2.0. If a copy of the MPL was not distributed with this
--   file, You can obtain one at http://mozilla.org/MPL/2.0/.

{-# OPTIONS_GHC -Wno-missing-methods #-}
{-# OPTIONS_HADDOCK show-extensions #-}

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

-- | Collection of functions, types and type families that are needed to implement type-safe private claims.
--
--   This is essentially an implementation of /open product/ type as described in Sandy Maguire "Thinking with Types".
--   The only difference to the book is that the implementation is backed by HashMap to make lookups by name easier.
--   In addition, there are also 'FromPrivateClaims' and 'ToPrivateClaims' type-classes and 
--   /view pattern/ ':<' to help create and deconstruct values.
module Libjwt.PrivateClaims
  ( 
    -- * Kinds
    Claim(..)
  , type (->>)
  , Namespace(..)
  , KnownNamespace(..)
  -- * Value-level counterparts
  , ClaimName(..)
  , claimNameVal
  , Ns(..)
  , ClaimWitness
  , testify
  , (->>)
  -- * Private claims type
  , PrivateClaims
  , type Empty
  -- * Construction
  , nullClaims
  , addClaim
  , (.:)
  , CanAdd
  , RestrictedName
  -- * Lookup
  , getClaim
  , (.!)
  , CanGet
  , LookupClaimType
  -- * Patern matching
  , pattern (:<)
  -- * Namespaces
  , withNs
  , someNs
  , noNs
  -- * Conversions
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

import           Data.Kind                      ( Constraint, Type )

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

-- | Kind of claims
--   
--   A claim is made up of a type-level literal and a type (this is essentialy a /type-level tuple/ @(Symbol, *)@)
data Claim (a :: Type) = Grant Symbol a

-- | A convenient alias.
--   Let's you write @'["claimName" ->> Int, "anotherName" ->> String]@ to indicate a list of types of kind 'Claim',
--   instead of @'[Grant "claimName" Int, Grant "anotherName" String]@,
--   
type name ->> a = 'Grant name a

-- | Kind of namespaces
--
--   These types represent a URL-like claim prefix
data Namespace = NoNs | SomeNs Symbol

-- | Class of 'Namespace' with known compile-time value
class KnownNamespace (ns :: Namespace) where
  -- | Convert namespace to a string (if any)
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

-- | Type-level literal representing a claim name
--
--   Can be used with @-XOverloadedLabels@
data ClaimName (name :: Symbol) = ClaimName

instance (name ~ name') => IsLabel name (ClaimName name') where
  fromLabel = ClaimName

-- | Retrieve the string associated with 'ClaimName'
claimNameVal :: forall name . KnownSymbol name => ClaimName name -> String
claimNameVal _ = symbolVal (Proxy :: Proxy name)

-- | Type-level literal representing a namespace
--
--   Can be used with @-XOverloadedLabels@ 
--  (the limited label syntax makes this rarely possibble though, a more common use is to write /Ns @"https://example.com"/)
data Ns (ns :: Symbol) = Ns

instance (name ~ name') => IsLabel name (Ns name') where
  fromLabel = Ns

-- | Keeps the value of type @a@ and the name (type-level) with which it is associated
newtype ClaimWitness (name :: Symbol) a = Witness { testify :: a }

-- | Associate @name@ with a value
--
--   With @-XOverloadedLabels@
--
-- >>> :t #someName ->> True
-- #someName ->> True :: ClaimWitness "someName" Bool
(->>) :: ClaimName name -> a -> ClaimWitness name a
_ ->> a = Witness a

data Any = forall a . Any a

-- | Container of named claims @ts@, possibly prefixed with some namespace @ns@
--   
--   For example @PrivateClaims '["string" t'->>' String, "int" t'->>' Int] ''NoNs'@ denotes a structure containing
--   a String under the "string" key plus an int under the "int" key.
--   There is no namespace, so the keys will not be prefixed by any prefix when serializing the structure
newtype PrivateClaims (ts :: [Claim Type]) (ns :: Namespace) = PrivateClaims { unsafeClaimsMap :: HashMap String Any }

type Empty = ('[] :: [Claim Type])

-- | Empty claims
nullClaims :: PrivateClaims Empty 'NoNs
nullClaims = PrivateClaims HashMap.empty

-- | Insert the claim.
--
--   The claim can be safely added iff:
--
--       * there is no claim of the same @name@ in the container,
--       * its name is not the name of any public claim (like /iss/ or /sub/)
--
--   Otherwise it is a compile-time error (see 'CanAdd' constraint)
--   
--   With @-XOverloadedLabels@
--
-- >>> addClaim #string "Value of claim" nullClaims
-- (#string ->> "Value of claim")
--
--   With @-XTypeApplications@ and @-XDataKinds@
--
-- >>> addClaim (ClaimName @"string") "Value of claim" nullClaims
-- (#string ->> "Value of claim")
addClaim
  :: forall name a ts ns
   . CanAdd name ts
  => ClaimName name
  -> a
  -> PrivateClaims ts ns
  -> PrivateClaims (name ->> a : ts) ns
addClaim _ a (PrivateClaims store) = PrivateClaims
  $ HashMap.insert claimName (Any a) store
  where claimName = symbolVal (Proxy :: Proxy name)

-- | Alias for 'addClaim' (binds to the right)
--
--   With @-XOverloadedLabels@
--
-- >>> #string ->> "Value of claim" .: nullClaims
-- (#string ->> "Value of claim")
(.:)
  :: forall name a ts ns
   . CanAdd name ts
  => ClaimWitness name a
  -> PrivateClaims ts ns
  -> PrivateClaims (name ->> a : ts) ns
(Witness a) .: pc = addClaim ClaimName a pc

-- | Constraint specifying when a claim named @n@ can be added to the list of claims @ns@
--
--   Satisfied iff:
--
--       * @n@ is a type-level literal,
--       * in the names of @ns@ claims there is no @n@ (uniqueness),
--       * @n@ is not one of the restricted names (see 'RestrictedName')
--
-- >>> :kind! CanAdd "name" '["n1" ->> Int, "n2" ->> String]
-- CanAdd "name" '["n1" ->> Int, "n2" ->> String] :: Constraint
-- = (GHC.TypeLits.KnownSymbol "name", () :: Constraint,
--   () :: Constraint)
--
-- >>> :kind! CanAdd "n1" '["n1" ->> Int, "n2" ->> String]
-- CanAdd "n1" '["n1" ->> Int, "n2" ->> String] :: Constraint
-- = (GHC.TypeLits.KnownSymbol "n1", () :: Constraint,
--   (TypeError ...))
type family CanAdd n ns :: Constraint where
  CanAdd n ns = (KnownSymbol n, DisallowRestrictedName (RestrictedName n) n, RequireUniqueName (UniqueName n ns) n)

type family UniqueName (name :: Symbol) (ts :: [Claim Type]) :: Bool where
  UniqueName _ '[]           = 'True
  UniqueName n (n ->> _ : _) = 'False
  UniqueName n (_ : rest)    = UniqueName n rest

type family RequireUniqueName (isUnique :: Bool) (name :: Symbol) :: Constraint where
  RequireUniqueName 'True  _  = ()
  RequireUniqueName 'False n  = TypeError ('Text "Claim " ':<>: 'ShowType n ':<>: 'Text " is not unique in this claim set")

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

unsafeLookup :: String -> PrivateClaims ts ns -> p
unsafeLookup claimName pc = unAny $ unsafeClaimsMap pc ! claimName
  where unAny (Any a) = unsafeCoerce a

-- | Look up the claim value associated with @name@.
--
--   Value can be retrieved if proven to exists in the container.
--   Otherwise it is a compile-time error (see 'CanGet' constraint)
--   
--   With @-XOverloadedLabels@
--
-- >>> getClaim #bool $ #string ->> "Value of claim" .: #bool ->> False .: nullClaims
-- False
getClaim
  :: forall name ts ns
   . CanGet name ts
  => ClaimName name
  -> PrivateClaims ts ns
  -> LookupClaimType name ts
getClaim _ = unsafeLookup name where name = symbolVal (Proxy :: Proxy name)
{-# INLINE getClaim #-}

-- | Alias for 'getClaim' (container goes first)
--
--   With @-XOverloadedLabels@
--
-- >>> (#string ->> "Value of claim" .: #bool ->> False .: nullClaims) .! #bool
-- False
(.!)
  :: forall name ts ns
   . CanGet name ts
  => PrivateClaims ts ns
  -> ClaimName name
  -> LookupClaimType name ts
pc .! name = getClaim name pc

-- | Constraint specifying when a claim named @n@ can be looked up in the list of claims @ns@
--
--   Satisfied iff @ns@ contains a claim named @n@ and @n@ is a type-level literal
--
-- >>> :kind! CanGet "n1" '["n1" ->> Int, "n2" ->> String]
-- CanGet "n1" '["n1" ->> Int, "n2" ->> String] :: Constraint
-- = (GHC.TypeLits.KnownSymbol "n1", () :: Constraint)
--
-- >>> :kind! CanGet "n" '["n1" ->> Int, "n2" ->> String]
-- CanGet "n" '["n1" ->> Int, "n2" ->> String] :: Constraint
-- = (GHC.TypeLits.KnownSymbol "n", (TypeError ...))
type family CanGet n ns :: Constraint where
  CanGet n ns = (KnownSymbol n, RequireExists (NameExists n ns) n)

-- | Looks up the type associated with @name@ in the @'[n1 t'->>' a, n2 t'->>' b, ...]@ pairs list. Gets stuck if @name@ is not in @ts@
--
-- >>> :kind! LookupClaimType "n1" '["n1" ->> Int, "n2" ->> String]
-- LookupClaimType "n1" '["n1" ->> Int, "n2" ->> String] :: *
-- = Int
type family LookupClaimType (name :: Symbol) (ts :: [Claim Type]) :: Type where
  LookupClaimType n (n ->> a : _) = a
  LookupClaimType n (_ : rest)    = LookupClaimType n rest

type family NameExists (name :: Symbol) (ts :: [Claim Type]) :: Bool where
  NameExists _ '[]           = 'False
  NameExists n (n ->> _ : _) = 'True
  NameExists n (_ : rest )   = NameExists n rest

type family RequireExists (exists :: Bool) (name :: Symbol) :: Constraint where
  RequireExists 'True  _ = ()
  RequireExists 'False n = TypeError ('Text "Claim " ':<>: 'ShowType n ':<>: 'Text " does not exist in this claim set")

getTail :: PrivateClaims (name ->> a : tl) ns -> PrivateClaims tl ns
getTail = coerce

view :: forall name a tl ns . KnownSymbol name => PrivateClaims (name ->> a : tl) ns -> (a, PrivateClaims tl ns)
view pc = (a, tl)
 where
   a = pc .! (ClaimName @name)
   tl = getTail pc

-- | Extract values from the container in the order in which they appear in the claim list
pattern (:<) :: KnownSymbol name => a -> PrivateClaims tl ns -> PrivateClaims (name ->> a : tl) ns
pattern head :< tail <- (view -> (head, tail))

{-# COMPLETE (:<) :: PrivateClaims #-}

-- | Convert to private claims with some namespace
withNs
  :: ToPrivateClaims a => Ns ns -> a -> PrivateClaims (Claims a) ( 'SomeNs ns)
withNs _ = coerce . toPrivateClaims

-- | Set namespace
someNs :: Ns ns -> PrivateClaims ts 'NoNs -> PrivateClaims ts ( 'SomeNs ns)
someNs _ = coerce

-- | Unset namespace
noNs :: PrivateClaims ts any -> PrivateClaims ts 'NoNs
noNs = coerce

getHead
  :: forall name a tl ns . (KnownSymbol name, KnownNamespace ns) => PrivateClaims (name ->> a : tl) ns -> (String, a)
getHead pc = (fullClaimName (Proxy :: Proxy ns) claimName, claimValue)
 where
  claimName = symbolVal (Proxy :: Proxy name)
  claimValue = unsafeLookup claimName pc
{-# INLINE getHead #-}

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
  decodeAux :: JwtT -> JwtIO (ClaimWitness name a)

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
  pc1 == pc2 = pc1 .! (ClaimName @name) == pc2 .! (ClaimName @name) && getTail pc1 == getTail pc2

-- | Class of types that can be converted to 'PrivateClaims'
class ToPrivateClaims a where
  type Claims a :: [Claim Type]
  type Claims a = ClaimsFromRecord (Rep a)

  type OutNs a :: Namespace
  type OutNs a = 'NoNs

  -- | Convert to claims
  toPrivateClaims :: a -> PrivateClaims (Claims a) (OutNs a)

  default toPrivateClaims
    :: ( Generic a
       , RecordToPrivateClaims (Rep a)
       , Claims a ~ ClaimsFromRecord (Rep a)
       , OutNs a ~ 'NoNs
       )
    => a -> PrivateClaims (Claims a) (OutNs a)
  toPrivateClaims = genericToPrivateClaims . from

-- | Class of types that can be constructed from @PrivateClaims@
class FromPrivateClaims a where
  -- | Convert from claims
  fromPrivateClaims :: ts ~ Claims a => PrivateClaims ts ns -> a

  default fromPrivateClaims 
    :: ( Generic a
       , RecordFromPrivateClaims (Rep a)
       , ts ~ ClaimsFromRecord(Rep a)
       ) 
    => PrivateClaims ts ns -> a
  fromPrivateClaims = to . genericFromPrivateClaims

class RecordToPrivateClaims g where
  type ClaimsFromRecord g :: [Claim Type]

  genericToPrivateClaims :: g p -> PrivateClaims (ClaimsFromRecord g) 'NoNs

class RecordFromPrivateClaims g where
  genericFromPrivateClaims :: PrivateClaims (ClaimsFromRecord g) ns -> g p

instance RecordToPrivateClaims c => RecordToPrivateClaims (D1 m c) where
  type ClaimsFromRecord (D1 m c) = ClaimsFromRecord c

  genericToPrivateClaims (M1 c) = genericToPrivateClaims c

instance RecordFromPrivateClaims c => RecordFromPrivateClaims (D1 m c) where
  genericFromPrivateClaims = M1 . genericFromPrivateClaims

instance RecordToPrivateClaims f => RecordToPrivateClaims (C1 m f) where
  type ClaimsFromRecord (C1 m f) = ClaimsFromRecord f

  genericToPrivateClaims (M1 f) = genericToPrivateClaims f

instance RecordFromPrivateClaims f => RecordFromPrivateClaims (C1 m f) where
  genericFromPrivateClaims = M1 . genericFromPrivateClaims 

type family (+++) (lhs :: [k]) (rhs :: [k]) :: [k] where
  '[]        +++ rhs = rhs
  (a : rest) +++ rhs = a : (rest +++ rhs)

instance (RecordToPrivateClaims s1, RecordToPrivateClaims s2) => RecordToPrivateClaims (s1 :*: s2) where
  type ClaimsFromRecord (s1 :*: s2) = ClaimsFromRecord s1 +++ ClaimsFromRecord s2

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
  type ClaimsFromRecord (S1 s (Rec0 a)) = '[SelectorName s ->> a]

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
  type Claims () = Empty

  toPrivateClaims _ = nullClaims

instance CanAdd n '[] => ToPrivateClaims (ClaimWitness n a) where
  type Claims (ClaimWitness n a) = '[n ->> a]
  toPrivateClaims (Witness a) = addClaim ClaimName a nullClaims

instance (CanAdd n2 '[], CanAdd n1 '[n2 ->> b]) => ToPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b) where
  type Claims (ClaimWitness n1 a, ClaimWitness n2 b) = '[n1 ->> a, n2 ->> b]
  toPrivateClaims (Witness a, Witness b) =
    addClaim ClaimName a $ addClaim ClaimName b nullClaims

instance (KnownSymbol n1, KnownSymbol n2) => FromPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b) where
  fromPrivateClaims (a :< b :< _) = (Witness a, Witness b)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c]
  , CanAdd n2 '[n3 ->> c]
  , CanAdd n3 '[]
  )
  => ToPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c) where
  type Claims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c) = '[n1 ->> a, n2 ->> b, n3 ->> c]
  toPrivateClaims (Witness a, Witness b, Witness c) =
    addClaim ClaimName a $
    addClaim ClaimName b $
    addClaim ClaimName c nullClaims

instance 
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  ) => FromPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c) where
  fromPrivateClaims (a :< b :< c :< _) = (Witness a, Witness b ,Witness c)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d]
  , CanAdd n2 '[n3 ->> c, n4 ->> d]
  , CanAdd n3 '[n4 ->> d]
  , CanAdd n4 '[]
  )
  => ToPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c, ClaimWitness n4 d) where
  type Claims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c, ClaimWitness n4 d) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d]
  toPrivateClaims (Witness a, Witness b, Witness c, Witness d) =
    addClaim ClaimName a $
    addClaim ClaimName b $
    addClaim ClaimName c $
    addClaim ClaimName d nullClaims

instance 
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  ) 
  => FromPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c, ClaimWitness n4 d) where
  fromPrivateClaims (a :< b :< c :< d :< _) =
    (Witness a, Witness b, Witness c, Witness d)

instance
  ( CanAdd n1 '[n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e]
  , CanAdd n2 '[n3 ->> c, n4 ->> d, n5 ->> e]
  , CanAdd n3 '[n4 ->> d, n5 ->> e]
  , CanAdd n4 '[n5 ->> e]
  , CanAdd n5 '[]
  )
  => ToPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c, ClaimWitness n4 d, ClaimWitness n5 e) where
  type Claims
    ( ClaimWitness n1 a
    , ClaimWitness n2 b
    , ClaimWitness n3 c
    , ClaimWitness n4 d
    , ClaimWitness n5 e) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e) =
    addClaim ClaimName a $
    addClaim ClaimName b $
    addClaim ClaimName c $
    addClaim ClaimName d $
    addClaim ClaimName e nullClaims

instance
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  , KnownSymbol n5
  )
  => FromPrivateClaims (ClaimWitness n1 a, ClaimWitness n2 b, ClaimWitness n3 c, ClaimWitness n4 d, ClaimWitness n5 e) where
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
     ( ClaimWitness n1 a
     , ClaimWitness n2 b
     , ClaimWitness n3 c
     , ClaimWitness n4 d
     , ClaimWitness n5 e
     , ClaimWitness n6 f) where
  type Claims
    ( ClaimWitness n1 a
    , ClaimWitness n2 b
    , ClaimWitness n3 c
    , ClaimWitness n4 d
    , ClaimWitness n5 e
    , ClaimWitness n6 f) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f) =
    addClaim ClaimName a $
    addClaim ClaimName b $
    addClaim ClaimName c $
    addClaim ClaimName d $
    addClaim ClaimName e $
    addClaim ClaimName f nullClaims

instance   
  ( KnownSymbol n1
  , KnownSymbol n2
  , KnownSymbol n3
  , KnownSymbol n4
  , KnownSymbol n5
  , KnownSymbol n6
  )
  =>  FromPrivateClaims
      ( ClaimWitness n1 a
      , ClaimWitness n2 b
      , ClaimWitness n3 c
      , ClaimWitness n4 d
      , ClaimWitness n5 e
      , ClaimWitness n6 f) where
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
    ( ClaimWitness n1 a
    , ClaimWitness n2 b
    , ClaimWitness n3 c
    , ClaimWitness n4 d
    , ClaimWitness n5 e
    , ClaimWitness n6 f
    , ClaimWitness n7 g) where
  type Claims
    ( ClaimWitness n1 a
    , ClaimWitness n2 b
    , ClaimWitness n3 c
    , ClaimWitness n4 d
    , ClaimWitness n5 e
    , ClaimWitness n6 f
    , ClaimWitness n7 g) = '[n1 ->> a, n2 ->> b, n3 ->> c, n4 ->> d, n5 ->> e, n6 ->> f, n7 ->> g]

  toPrivateClaims (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f, Witness g) =
    addClaim ClaimName a $
    addClaim ClaimName b $
    addClaim ClaimName c $
    addClaim ClaimName d $
    addClaim ClaimName e $
    addClaim ClaimName f $
    addClaim ClaimName g nullClaims

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
     ( ClaimWitness n1 a
     , ClaimWitness n2 b
     , ClaimWitness n3 c
     , ClaimWitness n4 d
     , ClaimWitness n5 e
     , ClaimWitness n6 f
     , ClaimWitness n7 g) where
  fromPrivateClaims (a :< b :< c :< d :< e :< f :< g :< _) =
    (Witness a, Witness b, Witness c, Witness d, Witness e, Witness f, Witness g)
   

instance ToPrivateClaims (PrivateClaims ts ns) where
  type Claims (PrivateClaims ts ns) = ts
  type OutNs (PrivateClaims ts ns) = ns
  toPrivateClaims = id

