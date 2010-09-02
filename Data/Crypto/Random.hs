{-# LANGUAGE ScopedTypeVariables, MonoLocalBinds #-}
module Data.Crypto.Random
	( OldRandomClass (..)
	, RandomGenerator(..)
	, genInteger
	, GenError (..)
	, newGenIO
	) where

import System.Crypto.Random (getEntropy)
import System.Random (RandomGen(..))
import Control.Monad (liftM)
import Data.Serialize
import qualified Data.ByteString as B
import Foreign.Storable (sizeOf)
import Data.Tagged
import Data.Bits (xor, setBit, shiftR, shiftL)

data GenError =			-- Expected use:
	  GenErrorOther String	-- Misc
	| RequestedTooManyBytes	-- Requested more bytes than a single pass can generate (ex: genBytes g i | i > 2^(2^32))
	| RangeInvalid		-- When using genInteger g (l,h), l >= h.
	| NeedReseed		-- Some generators cease operation after too high a count without a reseed (ex: NIST SP 800-90)
	| NotEnoughEntropy	-- For instantiating new generators (or reseeding)
  deriving (Eq, Ord, Show)

instance (RandomGenerator g) => RandomGen (OldRandomClass g) where
	next (ORC g) =
		let (Right (bs, g')) = genBytes g (sizeOf res)
		    Right res = decode bs
		in (res, ORC g')
	split (ORC g) =
		let Right (a, g1) = genBytes g 512
		    Right (b, g2) = genBytes g1 512
		    Right new1 = newGen a
		    Right new2 = newGen b
		in (ORC new1, ORC new2)

-- |Any 'RandomGenerator' can be used where the 'RandomGen' class is needed
-- simply by wrapping with with the ORC constructor.  Any failures
-- (Left results from genBytes or newGen bs | B.length bs == 512) result
-- in a pattern match exception.  Such failures were simply assumed
-- not possible by the RandomGen class, hence there is no non-exception
-- way to indicate a failure.
data OldRandomClass a = ORC a
	deriving (Eq, Ord, Show)

-- |A class of random bit generators that allows for the possibility of failure,
-- reseeding, providing entropy at the same time as requesting bytes
class RandomGenerator g where
	-- |Instantiate a new random bit generator
	newGen :: B.ByteString -> Either GenError g

	-- |Length of input entropy necessary to instantiate or reseed a generator
	genSeedLength :: Tagged g Int

	-- |Obtain random data using a generator
	genBytes	:: g -> Int -> Either GenError (B.ByteString, g)

	-- |'genBytesAI g i entropy' generates 'i' random bytes and use the
	-- additional input 'entropy' in the generation of the requested data.
	genBytesAI	:: g -> Int -> B.ByteString -> Either GenError (B.ByteString, g)
	genBytesAI g len entropy =
		let res = genBytes g len
		in case res of
			Left err -> Left err
			Right (bs,g') ->
				let entropy' = B.append entropy (B.replicate (len - B.length entropy) 0)
				in Right (zwp' entropy' bs, g')

	-- |reseed a random number generator
	reseed		:: g -> B.ByteString -> Either GenError g

-- | This class exists to provide the contraversial "split" operation that was
-- part of 'RandomGen'.
class SplitableGenerator g where
	split :: g -> Either GenError (g,g)

-- |Use System.Crypto.Random to obtain entropy for newGen.
-- Only buggy RandomGenerator instances should fail.
newGenIO :: RandomGenerator g => IO (Either GenError g)
newGenIO = do
	let r = Right undefined
	    l = genSeedLength `for` (fromRight r)
	    fromRight (Right x) = x
	res <- liftM newGen (getEntropy l)
	return (res `asTypeOf` r)

-- |Obtain a tagged value for a particular instantiated type.
for :: Tagged a b -> a -> b
for t _ = unTagged t

-- |'genInteger g (low,high)' will generate an integer between [low, high] inclusivly.
-- This function has degraded (theoretically unbounded, probabilitically decent) performance
-- the closer your range size (high - low) is to 2^n+1 for large natural values of n.
genInteger :: RandomGenerator g => g -> (Integer, Integer) -> Either GenError (Integer, g)
genInteger g (low,high) 
	| high < low = genInteger  g (high,low)
	| high == low = Right (high, g)
	| otherwise = 
    let range = high - low
        nrBytes = base2Log range
        offset = genBytes g (fromIntegral nrBytes)
    in case offset of
        Left err -> Left err
        Right (bs,g') -> 
	    if nrBytes > fromIntegral (maxBound :: Int)
		then Left RangeInvalid
		else let res = low + (bs2i bs)
		     in if res > high then genInteger g' (low, high) else Right (res, g')

base2Log :: Integer -> Integer
base2Log i
	| i >= setBit 0 64 = 65 + base2Log (i `shiftR` 65)
	| i >= setBit 0 32 = 33 + base2Log (i `shiftR` 33)
	| i >= setBit 0 16 = 17 + base2Log (i `shiftR` 17)
	| i >= setBit 0 8  = 9  + base2Log (i `shiftR` 9)
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
