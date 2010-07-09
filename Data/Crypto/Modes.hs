module Data.Crypto.Modes
	( ecb, unEcb
	, cbc, unCbc
	, cfb, unCfb
	, ofb, unOfb
	, ecb', unEcb'
	, cbc', unCbc'
	, cfb', unCfb'
	, ofb', unOfb'
	-- , gmc
	-- , xts
	-- , ccm
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize
import qualified Data.Binary as Bin
import Data.Bits (xor)
import Data.Crypto.Classes

-- Initilization Vectors for key 'k' (IV k) are used
-- for various modes and guarrenteed to be blockSize
-- bits long.
data IV k = IV B.ByteString deriving (Eq, Ord, Show)

collect :: Int -> [B.ByteString] -> B.ByteString
collect 0 _ = []
collect _ [] = []
collect i (b:bs)
	| len < i  = b : collect (i - len) bs
        | len >= i = [B.take i b]
  where
  len = B.length b
{-# INLINE collect #-}

chunkFor :: (BlockCipher k) => k -> L.ByteString -> [B.ByteString]
chunkFor k = takeWhile (== blkSz. B.length) . map (B.concat . L.toChunks . fst) . iterate (L.splitAt (fromIntegral blkSz) . snd)
  where blkSz = (blockSize `for` k) `div` 8
{-# INLINE chunkFor #-}

chunkFor' :: (BlockCipher k) => k -> B.ByteString -> [B.ByteString]
chunkFor' k = takeWhile (== blkSz . B.length) . map fst . iterate (B.splitAt blkSz . snd)
  where blkSz = (blockSize `for` k) `div` 8
{-# INLINE chunkFor' #-}

cbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
cbc' k (IV v) plaintext = go plaintext v
  where
  zBytes = (blockSize `for` k) `div` 8
  go pt vec =
	let (b,bs) = B.splitAt zBytes pt
	in if B.length b /= zBytes
		then (B.empty, IV vec)	-- If we want padding then change this line
		else let (cts, vecFinal) = go bs ct
			 ct = encrypt k (B.zipWith xor b vec)
		     in (B.append ct cts, IV vecFinal)

unCbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
unCbc' k (IV v) ciphertext= go ciphertext v
  where
  zBytes = blockSize k `div` 8
  go ct vec =
	let (b,bs) = B.splitAt zBytes ct
	in if B.length b /= zBytes
		then (B.empty, IV vec)	-- consider throwing some sort or error here
		else let (pts, vecFinal) = go bs b
		         pt = B.zipWith xor (decrypt k b) vec
		      in (B.append pt pts, IV vecFinal)

cbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
cbc k (IV iv) pt = go pt iv
  where
  zBytes = (blockSize `for` k) `div` 8
  go pt vec =
	let (b,bs) = L.splitAt zBytes pt
	in if L.length b /= zBytes
		then (L.empty, IV vec)	-- consider padding
		else let (cts, vecFinal) = go bs ct
			 ct = encrypt k (B.zipWith xor b vec)
		     in (L.append ct cts, IV vecFinal)

unCbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unCbc k vec ciphertext = go ciphertext v
  where
  zBytes =  (blockSize `for` k) `div` 8
  go ct vec =
	let (b,bs) = L.splitAt zBytes ct
	in if L.length b /= zBytes
		then (L.empty, IV vec) -- consider throwing exception
		else let (pts, vecFinal) = go bs b
			 pt = L.zipWith xor (decrypt k b) vec
		     in (L.append pt pts, IV vecFinal)

ecb :: BlockCipher k => k -> L.ByteString -> L.ByteString
ecb k msg = 
unEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString

ecb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
ecb' k msg =
	let chunks = chunkFor k msg
	in B.concat $ map (encrypt k) chunks

unEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
unEcb' k ct =
	let chunks = chunkFor' k ct
	in B.concat $ map (decrypt k) chunks

cfb :: BlockCipher k => k -> IV k -> L.ByteString -> L.ByteString
cfb = unCfb

unCfb :: BlockCipher k => k -> IV k -> L.ByteString -> L.ByteString
unCfb k (IV bs) = L.zipWith xor (L.concat $ iterate (encrypt k) bs)

cfb' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString
cfb' = unCfb'

unCfb' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString
unCfb' k (IV bs) msg = B.zipWith xor (collect (B.length msg) (iterate (encrypt k) bs)) msg

ctr :: BlockCipher k => k -> Counter -> L.ByteString -> (L.ByteString, Counter)
ctr k (Ctr c) = L.zipWith xor (L.fromChunks $ map fst $ iterate (\(ct, cnt) -> (encrypt k cnt, incCtr cnt)) (c,c))

unCtr :: BlockCipher k => k -> Counter -> L.ByteString -> (L.ByteString, Counter)
unCtr = ctr

ctr' :: BlockCipher k => k -> Counter -> B.ByteString -> (B.ByteString, Counter)
unCtr' :: BlockCipher k => k -> Counter -> B.ByteString -> (B.ByteString, Counter)

ofb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
ofb k (IV iv) msg = L.zipWith xor pad msg
  where pad = L.concat (iterate (encrypt k) iv)

unOfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString , IV k)
unOfb k (IV iv) msg = L.zipWith xor pad msg
  where pad = L.concat (iterate (encrypt k) iv)

ofb' :: BlockCipher k => k ->  IV k -> B.ByteString -> (B.ByteString, IV k)
ofb' k (IV iv) msg = B.zipWith xor pad msg
  where pad = collect (B.length msg) (iterate (encrypt k) iv)

unOfb' :: blockCipher k => k -> IV k -> B.byteString -> (B.ByteString, IV k)
unOfb' k (IV iv) msg = B.ipWith xor pad msg
  where pad = collect (B.length msg) (iterate (encrypt k) iv)

buildIV :: B.ByteString -> Maybe (IV k)
getIV :: IO (IV k)

instance Serialize (IV k) where
instance Binary (IV k) where

-- See NIST SP 800-38A, Appendix B
buildCtr :: B.ByteString -> Counter
getCtr :: IO Counter
incCtr :: Counter -> Counter

instance Serialize (Counter k) where
instance Binary (Counter k) where

-- TODO: GCM, CMAC
-- Consider the AES-only modes of XTS, CCM
