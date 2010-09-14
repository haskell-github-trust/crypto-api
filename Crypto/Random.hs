{-# LANGUAGE ScopedTypeVariables, MonoLocalBinds, FlexibleInstances #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 


 This module is for instantiating cryptographically strong determinitic random bit generators (DRBGs, aka PRNGs)
 For the simple use case of using the system random number generator ('System.Crypto.Random') to seed the DRBG:

@   g <- newGenIO
@

 Users needing to provide their own entropy can call 'newGen' directly
 
@    entropy <- getEntropy nrBytes
    let generator = newGen entropy
@

-}

module Crypto.Random
	( AsRandomGen (..)
	, CryptoRandomGen(..)
	, SplittableGen(..)
	, genInteger
	, GenError (..)
	, newGenIO
	) where

import System.Crypto.Random (getEntropy)
import Crypto.Types
import System.Random (RandomGen(next))
import qualified System.Random as R
import Control.Monad (liftM)
import Data.Serialize
import qualified Data.ByteString as B
import Foreign.Storable (sizeOf)
import Data.Tagged
import Data.Bits (xor, setBit, shiftR, shiftL, (.&.))
import Data.List (foldl')

-- |many generators have these error conditions in common
data GenError =
	  GenErrorOther String	-- ^ Misc
	| RequestedTooManyBytes	-- ^ Requested more bytes than a single pass can generate (ex: genBytes g i | i > 2^(2^32))
	| RangeInvalid		-- ^ When using @genInteger g (l,h)@ and @logBase 2 (h - l) > (maxBound :: Int)@.
	| NeedReseed		-- ^ Some generators cease operation after too high a count without a reseed (ex: NIST SP 800-90)
	| NotEnoughEntropy	-- ^ For instantiating new generators (or reseeding)
  deriving (Eq, Ord, Show)

instance Monad (Either GenError) where
        return = Right
        fail   = Left . GenErrorOther
        (Left x) >>= _  = Left x
        (Right x) >>= f = f x

instance (SplittableGen g, CryptoRandomGen g) => RandomGen (AsRandomGen g) where
	next (AsRG g) =
		let (Right (bs, g')) = genBytes g (sizeOf res)
		    Right res = decode bs
		in (res, AsRG g')
	split (AsRG g) = let (a,b) = split g in (AsRG a, AsRG b)

-- |Any `CryptoRandomGen` can be used where the `RandomGen` class is needed
-- simply by wrapping with with the `AsRG` constructor.  Any failures
-- (Left results from genBytes or newGen) result
-- in a pattern match exception.  Such failures were simply assumed
-- not possible by the `RandomGen` class, hence there is no non-exception
-- way to indicate a failure.
data AsRandomGen a = AsRG a
	deriving (Eq, Ord, Show)

-- |A class of random bit generators that allows for the possibility of failure,
-- reseeding, providing entropy at the same time as requesting bytes
--
-- Minimum complete definition: `newGen`, `genSeedLength`, `genBytes`, `reseed`.
class CryptoRandomGen g where
	-- |Instantiate a new random bit generator
	newGen :: B.ByteString -> Either GenError g

	-- |Length of input entropy necessary to instantiate or reseed a generator
	genSeedLength :: Tagged g ByteLength

	-- |Obtain random data using a generator
	genBytes	:: g -> ByteLength -> Either GenError (B.ByteString, g)

	-- |@genBytesWithEntropy g i entropy@ generates @i@ random bytes and use the
	-- additional input @entropy@ in the generation of the requested data to
	-- increase the confidence our generated data is a secure random stream.
	--
	-- Default:
	-- 
	-- @
	--     genBytesWithEntropy g bytes entropy = xor entropy (genBytes g bytes)
	-- @
	genBytesWithEntropy	:: g -> ByteLength -> B.ByteString -> Either GenError (B.ByteString, g)
	genBytesWithEntropy g len entropy =
		let res = genBytes g len
		in case res of
			Left err -> Left err
			Right (bs,g') ->
				let entropy' = B.append entropy (B.replicate (len - B.length entropy) 0)
				in Right (zwp' entropy' bs, g')

	-- |reseed the generator
	reseed		:: g -> B.ByteString -> Either GenError g

-- | This class exists to provide the contraversial "split" operation that was
-- part of 'RandomGen'.  When combined with a CryptoRandomGen instance this provides
-- a method to lift CryptoGenRandom into the RandomGen class (via the `AsRnadomGen` wrapper)
class SplittableGen g where
	split :: g -> (g,g)

-- |Use "System.Crypto.Random" to obtain entropy for `newGen`.
newGenIO :: CryptoRandomGen g => IO g
newGenIO = do
	let r = undefined
	    l = genSeedLength `for` r
	res <- liftM newGen (getEntropy l)
	case res of
		Left _ -> newGenIO
		Right g -> return (g `asTypeOf` r)

-- |Obtain a tagged value for a particular instantiated type.
for :: Tagged a b -> a -> b
for t _ = unTagged t

-- |@genInteger g (low,high)@ will generate an integer between [low, high] inclusively, swapping the pair if high < low.
--
-- This function has degraded (theoretically unbounded, probabilitically decent) performance
-- the closer your range size (high - low) is to 2^n (from the top).
genInteger :: CryptoRandomGen g => g -> (Integer, Integer) -> Either GenError (Integer, g)
genInteger g (low,high)
	| high < low = genInteger  g (high,low)
	| high == low = Right (high, g)
	| otherwise = go g
  where
  mask   = foldl' setBit 0 [0 .. fromIntegral nrBits - 1]
  nrBits = base2Log range
  range  = high - low
  nrBytes = (nrBits + 7) `div` 8
  go gen =
	let offset = genBytes gen (fromIntegral nrBytes)
	in case offset of
        Left err -> Left err
        Right (bs,g') -> 
	    if nrBytes > fromIntegral (maxBound :: Int)
		then Left RangeInvalid
		else let res = low + (bs2i bs .&. mask)
		     in if res > high then go g' else Right (res, g')

base2Log :: Integer -> Integer
base2Log i
	| i >= setBit 0 64 = 64 + base2Log (i `shiftR` 64)
	| i >= setBit 0 32 = 32 + base2Log (i `shiftR` 32)
	| i >= setBit 0 16 = 16 + base2Log (i `shiftR` 16)
	| i >= setBit 0 8  = 8  + base2Log (i `shiftR` 8)
	| i >= setBit 0 0  = 1  + base2Log (i `shiftR` 1)
	| otherwise        = 0

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' a = B.pack . B.zipWith xor a
{-# INLINE zwp' #-}
