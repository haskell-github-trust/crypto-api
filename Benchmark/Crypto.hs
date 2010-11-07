{- |
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 


 Criterion benchmarks for hash and block ciphers.
 Example hash benchmark:

>	import Data.Digest.Pure.MD5
>	import Benchmark.Crypto
>	import Criterion.Main
>	main = defaultMain [benchmarkHash (undefined :: MD5Digest) "pureMD5"]

   example block cipher benchmark:

>	main = do
>	        let (Just k128) = buildKey (B.pack [0..15]) :: Maybe AESKey
>	            (Just k192) = buildKey (B.pack [0..23]) :: Maybe AESKey
>	            (Just k256) = buildKey (B.pack [0..31]) :: Maybe AESKey
>	        defaultMain     [ benchmarkBlockCipher k128 "SimpleAES-128"
>	                        , benchmarkBlockCipher k192 "SimpleAES-192"
>	                        , benchmarkBlockCipher k256 "SimpleAES-256"]
-}
module Benchmark.Crypto
	( benchmarkHash
	, benchmarkBlockCipher
	, benchmarkRNG
	, benchmarkCryptoRandomGen
	) where

import Crypto.Classes
import Crypto.Modes (ecb', unEcb')
import Crypto.Random
import qualified Data.Serialize as Ser
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize as Ser
import Criterion
import Control.Monad (liftM)
import Data.IORef

-- 128KB strings
ps = B.replicate (2^17) 0
lps = L.replicate (2^17) 0

-- 4MB strings
ps4MB = B.replicate (2^22) 0
lps4MB = B.replicate (2^22) 0

-- |Benchmark a hash by calling the 'hash' and 'hash'' functions
-- on 128KB bytestrings.
benchmarkHash :: Hash c d => d -> String -> Benchmark
benchmarkHash h name =
        let benchs = bgroup name [ bench "lazy"   (whnf (hashFunc h) lps)
				 , bench "strict" (whnf (hashFunc' h) ps)] :: Benchmark
	in benchs

op :: Ser.Serialize d => (a -> d) -> a -> Pure
op f str = whnf (B.unpack . Ser.encode . f) str

-- |Benchmark a block cipher by calling the 'ecb'' and 'unEcb'' functions
benchmarkBlockCipher :: BlockCipher k => k -> String -> Benchmark
benchmarkBlockCipher k name =
	let benchs = bgroup name [ bench "enc" (whnf (ecb' k) ps)
				 , bench "dec" (whnf (unEcb' k) ps)] :: Benchmark
	in benchs

-- |Benchmark an RNG by requesting 256K of random data
benchmarkRNG :: (Int -> IO B.ByteString) -> String -> Benchmark
benchmarkRNG rng name = bench name (nfIO $ liftM B.head (rng (2^18)))

-- | Benchmark a CryptoRandomGen by storing it in a IORef, and generating
-- 256k per call.
benchmarkCryptoRandomGen :: CryptoRandomGen g => g -> String -> IO Benchmark
benchmarkCryptoRandomGen g name = do
	g' <- useGenIO g
	return $ bench name (nfIO $ liftM B.head (g' (2^18)))

useGenIO :: CryptoRandomGen g => g -> IO (Int -> IO B.ByteString)
useGenIO g = do
        gRef <- newIORef g
        return $ \i -> do
        gen <- readIORef gRef
        let v = genBytes i gen
        case v of
                Left _ -> error "blah"
                Right (b,gen') -> do
                        writeIORef gRef gen'
                        return b

