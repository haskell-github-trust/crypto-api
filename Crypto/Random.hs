{-# LANGUAGE FlexibleInstances, TypeSynonymInstances #-}
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
	( CryptoRandomGen(..)
	, GenError (..)
	, newGenIO
	) where

import System.Crypto.Random (getEntropy)
import Crypto.Types
import Control.Monad (liftM)
import qualified Data.ByteString as B
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

-- |Use "System.Crypto.Random" to obtain entropy for `newGen`.
newGenIO :: CryptoRandomGen g => IO g
newGenIO = go 0
  where
  go 1000 = error "The generator instance requested by newGenIO never instantiates (1000 tries).  It must be broken."
  go i = do
	let p = Proxy
	    getTypedGen :: (CryptoRandomGen g) => Proxy g -> IO (Either GenError g)
	    getTypedGen pr = liftM newGen (getEntropy $ proxy genSeedLength pr)
	res <- getTypedGen p
	case res of
		Left _ -> go (i+1)
		Right g -> return (g `asProxyTypeOf` p)

-- |Obtain a tagged value for a particular instantiated type.
for :: Tagged a b -> a -> b
for t _ = unTagged t

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' a = B.pack . B.zipWith xor a
{-# INLINE zwp' #-}
