{-# LANGUAGE ScopedTypeVariables #-}
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
import qualified Data.Binary.Put as BP
import qualified Data.Binary.Get as BG
import qualified Data.Serialize.Put as SP
import qualified Data.Serialize.Get as SG
import Data.Bits (xor)
import Data.Crypto.Classes
import System.Random (RandomGen)

-- Initilization Vectors for key 'k' (IV k) are used
-- for various modes and guarrenteed to be blockSize
-- bits long.
data IV k = IV { initializationVector :: B.ByteString } deriving (Eq, Ord, Show)

data Counter k = Ctr { count :: B.ByteString } deriving (Eq, Ord, Show)

collect :: Int -> [B.ByteString] -> [B.ByteString]
collect 0 _ = []
collect _ [] = []
collect i (b:bs)
	| len < i  = b : collect (i - len) bs
        | len >= i = [B.take i b]
  where
  len = B.length b
{-# INLINE collect #-}

chunkFor :: (BlockCipher k) => k -> L.ByteString -> [B.ByteString]
chunkFor k = go
  where
  blkSz = (blockSize `for` k) `div` 8
  blkSzI = fromIntegral blkSz
  go bs | L.length bs < blkSzI = []
        | otherwise            = let (blk,rest) = L.splitAt blkSzI bs in B.concat (L.toChunks blk) : go rest
{-# INLINE chunkFor #-}

chunkFor' :: (BlockCipher k) => k -> B.ByteString -> [B.ByteString]
chunkFor' k = go
  where
  blkSz = (blockSize `for` k) `div` 8
  go bs | B.length bs < blkSz = []
        | otherwise           = let (blk,rest) = B.splitAt blkSz bs in blk : go rest
{-# INLINE chunkFor' #-}

-- |zipWith xor + Pack
-- This is written intentionally to take advantage of the bytestring
-- libraries 'zipWith'' rewrite rule but at the extra cost of the
-- resulting lazy bytestring being more fragmented than either of the
-- two inputs.
zwp  a b = 
	let as = L.toChunks a
	    bs = L.toChunks b
	in L.fromChunks (go as bs)
  where
  go [] _ = []
  go _ [] = []
  go (a:as) (b:bs) =
	let l = min (B.length a) (B.length b)
	    (a',ar) = B.splitAt l a
	    (b',br) = B.splitAt l b
	    as' = if B.length ar == 0 then as else ar : as
	    bs' = if B.length br == 0 then bs else br : bs
	in (zwp' a' b') : go as' bs'

-- |zipWith xor + Pack
--This should be optimized to use the bytestring libraries 'zipWith'' function due to rewrite rules.
zwp' a = B.pack . B.zipWith xor a

-- |Cipher block chaining encryption mode on strict bytestrings
cbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
cbc' k (IV v) plaintext =
	let blks = chunkFor' k plaintext
	    (cts, iv) = go blks v
	in (B.concat cts, IV iv)
  where
  go [] iv = ([], iv)
  go (b:bs) iv =
	let c = encryptBlock k (zwp' iv b)
	    (cs, ivFinal) = go bs c
	in (c:cs, ivFinal)

-- |Cipher block chaining decryption for strict bytestrings
unCbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
unCbc' k (IV v) ciphertext =
	let blks = chunkFor' k ciphertext
	    (pts, iv) = go blks v
	in (B.concat pts, IV iv)
  where
  go [] iv = ([], iv)
  go (c:cs) iv =
	let p = zwp' (decryptBlock k c) iv
	    (ps, ivFinal) = go cs c
	in (p:ps, ivFinal)

-- |Cipher block chaining encryption for lazy bytestrings
cbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
cbc k (IV v) plaintext =
	let blks = chunkFor k plaintext
	    (cts, iv) = go blks v
	in (L.fromChunks cts, IV iv)
  where
  go [] iv = ([], iv)
  go (b:bs) iv =
	let c = encryptBlock k (zwp' iv b)
	    (cs, ivFinal) = go bs c
	in (c:cs, ivFinal)

-- |Cipher block chaining decryption for lazy bytestrings
unCbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unCbc k (IV v) ciphertext =
	let blks = chunkFor k ciphertext
	    (pts, iv) = go blks v
	in (L.fromChunks pts, IV iv)
  where
  go [] iv = ([], iv)
  go (c:cs) iv =
	let p = zwp' (decryptBlock k c) iv
	    (ps, ivFinal) = go cs c
	in (p:ps, ivFinal)

ecb :: BlockCipher k => k -> L.ByteString -> L.ByteString
ecb k msg =
	let chunks = chunkFor k msg
	in L.fromChunks $ map (encryptBlock k) chunks

unEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString
unEcb k msg =
	let chunks = chunkFor k msg
	in L.fromChunks $ map (decryptBlock k) chunks

ecb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
ecb' k msg =
	let chunks = chunkFor' k msg
	in B.concat $ map (encryptBlock k) chunks

unEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
unEcb' k ct =
	let chunks = chunkFor' k ct
	in B.concat $ map (decryptBlock k) chunks

-- |Ciphertext feed-back encryption mode with s == blockSize
cfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
cfb k (IV v) msg =
	let blks = chunkFor k msg
	    (cs,ivF) = go v blks
	in (L.fromChunks cs, IV ivF)
  where
  go iv [] = ([],iv)
  go iv (b:bs) =
	let c = zwp' (encryptBlock k iv) b
	    (cs,ivFinal) = go c bs
	in (c:cs, ivFinal)

unCfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unCfb k (IV v) msg = 
	let blks = chunkFor k msg
	    (ps, ivF) = go v blks
	in (L.fromChunks ps, IV ivF)
  where
  go iv [] = ([], iv)
  go iv (b:bs) =
	let p = zwp' (encryptBlock k iv) b
	    (ps, ivF) = go b bs
	in (p:ps, ivF)

cfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
cfb' k (IV v) msg =
	let blks = chunkFor' k msg
	    (cs,ivF) = go v blks
	in (B.concat cs, IV ivF)
  where
  go iv [] = ([],iv)
  go iv (b:bs) =
	let c = zwp' (encryptBlock k iv) b
	    (cs,ivFinal) = go c bs
	in (c:cs, ivFinal)

unCfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
unCfb' k (IV v) msg =
	let blks = chunkFor' k msg
	    (ps, ivF) = go v blks
	in (B.concat ps, IV ivF)
  where
  go iv [] = ([], iv)
  go iv (b:bs) =
	let p = zwp' (encryptBlock k iv) b
	    (ps, ivF) = go b bs
	in (p:ps, ivF)

ofb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
ofb = unOfb

unOfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unOfb k (IV iv) msg =
	let ivStr = iterate (encryptBlock k) iv
	    ivLen = fromIntegral (B.length iv)
	    newIV = IV . B.concat . L.toChunks . L.take ivLen . L.drop (L.length msg) . L.fromChunks $ ivStr
	in (zwp (L.fromChunks ivStr) msg, newIV)

ofb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
ofb' = unOfb'

unOfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
unOfb' k (IV iv) msg =
	let ivStr = collect (B.length msg + ivLen) (iterate (encryptBlock k) iv)
	    ivLen = B.length iv
	    mLen = fromIntegral (B.length msg)
	    newIV = IV . B.concat . L.toChunks . L.take (fromIntegral ivLen) . L.drop mLen . L.fromChunks $ ivStr
	in (zwp' (B.concat ivStr) msg, newIV)

ctr :: BlockCipher k => k -> Counter k -> L.ByteString -> (L.ByteString, Counter k)
ctr k (Ctr counter) msg =
	let blks = chunkFor k msg
	    (cs, cnt') = go counter blks
	in (L.fromChunks cs, Ctr cnt')
  where
  go cnt [] = ([], cnt)
  go cnt (b:bs) =
	let c = zwp' (encryptBlock k cnt) b
	    (Ctr cnt') = incCtr (Ctr cnt)
	    (cs, cntFinal) = go cnt' bs
	in (c:cs, cntFinal)

unCtr :: BlockCipher k => k -> Counter k -> L.ByteString -> (L.ByteString, Counter k)
unCtr = ctr
	    

ctr' :: BlockCipher k => k -> Counter k -> B.ByteString -> (B.ByteString, Counter k)
ctr' k (Ctr counter) msg = 
	let blks = chunkFor' k msg
	    (cs, cnt') = go counter blks
	in (B.concat cs, Ctr cnt')
  where
  go cnt [] = ([], cnt)
  go cnt (b:bs) =
	let c = zwp' (encryptBlock k cnt) b
	    (Ctr cnt') = incCtr (Ctr cnt)
	    (cs, cntFinal) = go cnt' bs
	in (c:cs, cntFinal)

unCtr' :: BlockCipher k => k -> Counter k -> B.ByteString -> (B.ByteString, Counter k)
unCtr' = ctr'

getIV :: RandomGen g => g -> (IV k, g)
getIV = undefined

ivBlockSizeBytes :: BlockCipher k => IV k -> Int
ivBlockSizeBytes iv = (blockSize `for` (keyForIV iv)) `div` 8
  where
  keyForIV :: IV k -> k
  keyForIV _ = undefined

instance (BlockCipher k) => Serialize (IV k) where
	get = do
	  	let bytes = blockSize .::. (undefined :: k) `div` 8
		iv <- SG.getByteString bytes
		return (IV iv)
	put (IV iv) = SP.putByteString iv

instance BlockCipher k => Bin.Binary (IV k) where
	get = do
		let bytes = blockSize .::. (undefined :: k) `div` 8
		iv <- BG.getByteString bytes
		return (IV iv)
	put (IV iv) = BP.putByteString iv

-- See NIST SP 800-38A, Appendix B
getCtr :: RandomGen g => g -> (Counter k, g)
getCtr = undefined
incCtr :: Counter k -> Counter k
incCtr = undefined

instance BlockCipher k => Serialize (Counter k) where
	get = do
	  	let bytes = blockSize .::. (undefined :: k) `div` 8
		c <- SG.getByteString bytes
		return (Ctr c)
	put (Ctr c) = SP.putByteString c

instance BlockCipher k => Bin.Binary (Counter k) where
	get = do
	  	let bytes = blockSize .::. (undefined :: k) `div` 8
		c <- BG.getByteString bytes
		return (Ctr c)
	put (Ctr c) = BP.putByteString c

-- TODO: GCM, GMAC
-- Consider the AES-only modes of XTS, CCM
