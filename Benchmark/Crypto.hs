module Benchmark.Crypto
	( benchmarkHash
	, benchmarkBlockCipher
	) where
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize as Ser
import Numeric
import Criterion
import Criterion.Config
import qualified Criterion.MultiMap as M

-- 128KB strings
ps = B.replicate (2^27) 0
lps = L.replicate (2^27) 0

benchHash :: Hash c d => d => String -> IO ()
benchHash h name = do
        let benchs = bgroup	[ bench (name ++ "-lazy")   (op (hashFunc h) lps)
				, bench (name ++ "-strict") (op (hashFunc' h) ps)]
	run benchs 1000

op :: Ser.Serizalize d => (a -> d) -> a -> Pure
op f str = whnf (B.unpack . Ser.encode . f) str

benchmarkBlockCipher :: BlockCipher k => k -> String -> IO ()
benchmarkBlockCipher k name =
	let benchs = bgroup 	[ bench (name ++ "-enc") (ecb k) ps
				, bench (name ++ "-dec") (ecb k) ps]
	run benchs 1000
