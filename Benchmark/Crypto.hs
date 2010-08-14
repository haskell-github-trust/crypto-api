module Benchmark.Crypto
	( benchmarkHash
	, benchmarkBlockCipher
	) where

import Data.Crypto.Classes
import Data.Crypto.Modes (ecb', unEcb')
import qualified Data.Serialize as Ser
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize as Ser
import Criterion
import Control.Monad (liftM)

-- 128KB strings
ps = B.replicate (2^27) 0
lps = L.replicate (2^27) 0

benchmarkHash :: Hash c d => d -> String -> Benchmark
benchmarkHash h name =
        let benchs = bgroup name [ bench "lazy"   (whnf (hashFunc h) lps)
				 , bench "strict" (whnf (hashFunc' h) ps)] :: Benchmark
	in benchs

op :: Ser.Serialize d => (a -> d) -> a -> Pure
op f str = whnf (B.unpack . Ser.encode . f) str

benchmarkBlockCipher :: BlockCipher k => k -> String -> Benchmark
benchmarkBlockCipher k name =
	let benchs = bgroup name [ bench "enc" (whnf (ecb' k) ps)
				 , bench "dec" (whnf (unEcb' k) ps)] :: Benchmark
	in benchs

benchmarkRNG :: (Int -> IO B.ByteString) -> String -> Benchmark
benchmarkRNG rng name = bench name (whnfIO (liftM B.unpack (rng (2^27))))
