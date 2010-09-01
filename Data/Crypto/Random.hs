module Data.Crypto.Random
	( OldRandomClass (..)
	, RandomGenerator(..)
	, genInteger
	, base2Log
	) where

import System.Random
import Data.Serialize
import qualified Data.ByteString as B
import Foreign.Storable (sizeOf)
import Data.Tagged
import Data.Bits (xor, setBit, shiftR, shiftL)

data GenError = GenErrorOther String | GenRequestedTooManyBytes

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

data OldRandomClass a = ORC a
	deriving (Eq, Ord, Show)

type Gen a g = Either GenError (a, g)

-- |A class of random bit generators that allows for the possibility of failure,
-- reseeding, providing entropy at the same time as requesting bytes
class RandomGenerator g where
	newGen :: B.ByteString -> Either GenError g
	genSeedLen :: Tagged g Int
	genBytes	:: g -> Int -> Either GenError (B.ByteString, g)

	-- |'genBytesAI g i entropy' generates 'i' random bytes and use the
	-- additional input 'entropy' in the generation of the requested data.
	genBytesAI	:: g -> Int -> B.ByteString -> Either GenError (B.ByteString, g)
	genBytesAI g len entropy =
		let res = genBytes g len
		in case res of
			Left err -> Left err
			Right (bs,g') -> Right (zwp' entropy bs, g')

	-- |reseed a random number generator
	reseed		:: g -> B.ByteString -> Either GenError g

-- 'genInteger g (low,high)' will generate an integer between [low, high] inclusivly.
genInteger :: RandomGenerator g => g -> (Integer, Integer) -> Either GenError (Integer, g)
genInteger g (low,high) =
    let range = high - low
        nrBytes = base2Log range
        offset = genBytes g (fromIntegral nrBytes)
    in case offset of
        Left err -> Left err
        Right (bs,g') -> 
            case decode bs of
	       Left str -> Left (GenErrorOther str)
               Right v  -> if nrBytes > fromIntegral (maxBound :: Int)
                             then Left (GenRequestedTooManyBytes)
                             else Right (low + v, g')

base2Log :: Integer -> Integer
base2Log i
	| i > setBit 0 64 = 64 + base2Log (i `shiftR` 64)
	| i > setBit 0 32 = 32 + base2Log (i `shiftR` 32)
	| i > setBit 0 16 = 16 + base2Log (i `shiftR` 16)
	| i > setBit 0 8  = 8  + base2Log (i `shiftR` 8)
	| i > setBit 0 0  = 1  + base2Log (i `shiftR` 1)
	| otherwise       = 0

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' a = B.pack . B.zipWith xor a
{-# INLINE zwp' #-}
