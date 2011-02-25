{-# LANGUAGE CPP #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 

 Generic mode implementations useable by any correct BlockCipher instance 
 
  Be aware there are no tests for CFB mode yet.  See "Test.Crypto".
-}
module Crypto.Modes
	(
	-- * Initialization Vector Type (for all ciphers for all modes that use IVs)
	  IV
	, getIV, getIVIO
	-- * Blockcipher modes of operation.  Note name' (with a prime) means strict, without a prime means lazy bytestrings.
	, ecb, unEcb
	, cbc, unCbc
	, cfb, unCfb
	, ofb, unOfb
	, ecb', unEcb'
	, cbc', unCbc'
	, cfb', unCfb'
	, ofb', unOfb'
	-- , cnt, unCnt
	, cnt', unCnt'
	-- * Authentication modes
	, cbcMac', cbcMac
	-- * Combined modes (nothing here yet)
	-- , gmc
	-- , xts
	-- , ccm
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize
import qualified Data.Serialize.Put as SP
import qualified Data.Serialize.Get as SG
import Data.Bits (xor, shiftR)
import Data.Tagged
import Crypto.Classes
import Crypto.Random
import Crypto.Util
import System.Crypto.Random (getEntropy)
import Control.Monad (liftM, forM_)

-- For CTR mode only:
import Data.Word
import Data.LargeWord
import Foreign.Storable
import Foreign.Ptr (castPtr, Ptr)
import qualified Data.ByteString.Internal as BI
import qualified Foreign.ForeignPtr as FP
import System.IO.Unsafe (unsafePerformIO)
import Data.ByteString.Unsafe (unsafeIndex, unsafeUseAsCString)

#if MIN_VERSION_tagged(0,2,0)
import Data.Proxy
#endif

-- |Counters for BlockCipher implementations are used for 
-- the counter modes.  These are not checked for roll-over!
-- implementations using 'ctr', 'ctr'', etc should be tracking
-- the number of plaintext blocks!
newtype Ctr k = Ctr { unCtr :: Integer }

-- |Initilization Vectors for BlockCipher implementations (IV k) are used
-- for various modes and guarrenteed to be blockSize bits long.  The common
-- ways to obtain an IV are to generate one ('getIV' or 'getIVIO') or to
-- use one provided with the ciphertext (using the 'Serialize' instance of IV).
data IV k = IV { initializationVector :: {-# UNPACK #-} !B.ByteString } deriving (Eq, Ord, Show)

-- gather a specified number of bytes from the list of bytestrings
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
zwp :: L.ByteString -> L.ByteString -> L.ByteString
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
{-# INLINEABLE zwp #-}

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' :: B.ByteString -> B.ByteString -> B.ByteString
zwp' a = B.pack . B.zipWith xor a
{-# INLINEABLE zwp' #-}

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
{-# INLINEABLE cbc' #-}

cbcMac' :: BlockCipher k => k -> B.ByteString -> B.ByteString
cbcMac' k pt = encode $ snd $ cbc' k (IV (B.replicate (blockSize `for` k) 0)) pt
{-# INLINEABLE cbcMac' #-}

cbcMac :: BlockCipher k => k -> L.ByteString -> L.ByteString
cbcMac k pt = L.fromChunks [encode $ snd $ cbc k (IV (B.replicate (blockSize `for` k) 0)) pt]
{-# INLINEABLE cbcMac #-}

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
{-# INLINEABLE unCbc' #-}

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
{-# INLINEABLE cbc #-}

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
{-# INLINEABLE unCbc #-}

ecb :: BlockCipher k => k -> L.ByteString -> L.ByteString
ecb k msg =
	let chunks = chunkFor k msg
	in L.fromChunks $ map (encryptBlock k) chunks
{-# INLINEABLE ecb #-}

unEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString
unEcb k msg =
	let chunks = chunkFor k msg
	in L.fromChunks $ map (decryptBlock k) chunks
{-# INLINEABLE unEcb #-}

ecb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
ecb' k msg =
	let chunks = chunkFor' k msg
	in B.concat $ map (encryptBlock k) chunks
{-# INLINEABLE ecb' #-}

unEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
unEcb' k ct =
	let chunks = chunkFor' k ct
	in B.concat $ map (decryptBlock k) chunks
{-# INLINEABLE unEcb' #-}

-- |Ciphertext feed-back encryption mode for lazy bytestrings (with s == blockSize)
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
{-# INLINEABLE cfb #-}

-- |Ciphertext feed-back decryption mode for lazy bytestrings (with s == blockSize)
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
{-# INLINEABLE unCfb #-}

-- |Ciphertext feed-back encryption mode for strict bytestrings (with s == blockSize)
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
{-# INLINEABLE cfb' #-}

-- |Ciphertext feed-back decryption mode for strict bytestrings (with s == blockSize)
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
{-# INLINEABLE unCfb' #-}

-- |Output feedback mode for lazy bytestrings
ofb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
ofb = unOfb
{-# INLINEABLE ofb #-}

-- |Output feedback mode for lazy bytestrings
unOfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unOfb k (IV iv) msg =
	let ivStr = drop 1 (iterate (encryptBlock k) iv)
	    ivLen = fromIntegral (B.length iv)
	    newIV = IV . B.concat . L.toChunks . L.take ivLen . L.drop (L.length msg) . L.fromChunks $ ivStr
	in (zwp (L.fromChunks ivStr) msg, newIV)
{-# INLINEABLE unOfb #-}

-- |Output feedback mode for strict bytestrings
ofb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
ofb' = unOfb'
{-# INLINEABLE ofb' #-}


-- |Counter mode
cnt' :: BlockCipher k => k -> Ctr k -> B.ByteString -> (B.ByteString, Ctr k)
cnt' k (Ctr cVal) pt =
	let len = B.length pt
	    blkSz  = blockSizeBytes `for` k
	    ptBlks = (len + (blkSz - 1)) `div` blkSz
	    req = blkSz * ptBlks
	    ctrs = unsafePerformIO $ do
		buf <- FP.mallocForeignPtrBytes req
		FP.withForeignPtr buf $ \ptr -> do
	  	  case blkSz of
		    32 -> genBytesCtr (undefined :: Word256) ptr req cVal
		    16 -> genBytesCtr (undefined :: Word128) ptr req cVal
		    8  -> genBytesCtr (undefined :: Word64) ptr req cVal
		    _  -> genBytesCtrGeneric blkSz ptr req cVal
	          return (BI.fromForeignPtr (FP.castForeignPtr buf) 0 req)
--	    ctrs = runPut $ forM_ (map (+fromIntegral cVal) [0..fromIntegral ptBlks-1]) (\i -> putWord64be 0 >> putWord64be i)
	    ct = encryptBlock k ctrs
	in (zwp' ct pt,  Ctr (cVal + fromIntegral ptBlks))
{-# INLINEABLE cnt' #-}

genBytesCtr :: (Storable w, Num w) => w -> Ptr x -> Int -> Integer -> IO ()
genBytesCtr wordUndef p req counter = do
  let nrW = (req + sizeOf wordUndef - 1) `div` (sizeOf wordUndef)
      ptr = castPtr p
      c = fromIntegral counter
  forM_ [0..nrW-1] $ \i ->
        pokeElemOff ptr i (c + fromIntegral i `asTypeOf` wordUndef)
{-# INLINE genBytesCtr #-}

genBytesCtrGeneric :: Int -> Ptr x -> Int -> Integer -> IO ()
genBytesCtrGeneric blkSz ptr req counter = do
        let nrB  = (req + blkSz - 1) `div` blkSz
            (fptr,_,_) = BI.toForeignPtr (B.concat [i2bs (blkSz*8) (counter + fromIntegral i) | i <- [0..nrB-1]])
        FP.withForeignPtr fptr $ \ptr' -> BI.memcpy (castPtr ptr) ptr' (fromIntegral $ nrB * blkSz)
{-# INLINE genBytesCtrGeneric #-}

unCnt' :: BlockCipher k => k -> Ctr k -> B.ByteString -> (B.ByteString, Ctr k)
unCnt' = cnt'
{-# INLINEABLE unCnt' #-}

-- |Ctr, nrBlocks, blkSzBits
incCnt :: Ctr k -> Int -> Int -> [B.ByteString]
incCnt c i blkSz 
    | blkSz `rem` 64 == 0 = [runPut $ mapM_ (c2bsE blkSz) [c'+1,c'+2.. c'+fromIntegral i]]
    | otherwise = map (c2bs blkSz) [c'+1, c'+2.. c'+fromIntegral i]
  where
  c' = unCtr c
  c2bs :: Int -> Integer -> B.ByteString
  c2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)
  c2bsE :: Int -> Integer -> Put
  c2bsE l i | l == 0 = return ()
            | otherwise = SP.putWord64be (fromIntegral i) >> c2bsE (l-64) (i `shiftR` 64)
{-# INLINE incCnt #-}

-- |Output feedback mode for strict bytestrings
unOfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
unOfb' k (IV iv) msg =
	let ivStr = collect (B.length msg + ivLen) (drop 1 (iterate (encryptBlock k) iv))
	    ivLen = B.length iv
	    mLen = fromIntegral (B.length msg)
	    newIV = IV . B.concat . L.toChunks . L.take (fromIntegral ivLen) . L.drop mLen . L.fromChunks $ ivStr
	in (zwp' (B.concat ivStr) msg, newIV)
{-# INLINEABLE unOfb' #-}

-- |Obtain an `IV` using the provided CryptoRandomGenerator.
getIV :: (BlockCipher k, CryptoRandomGen g) => g -> Either GenError (IV k, g)
getIV g =
	let bytes = ivBlockSizeBytes iv
	    gen = genBytes bytes g
	    fromRight (Right x) = x
	    iv  = IV (fst  . fromRight $ gen)
	in case gen of
		Left err -> Left err
		Right (bs,g')
			| B.length bs == bytes	-> Right (iv, g')
			| otherwise		-> Left (GenErrorOther "Generator failed to provide requested number of bytes")
{-# INLINEABLE getIV #-}

-- | Obtain an `IV` using the system entropy (see "System.Crypto.Random")
getIVIO :: (BlockCipher k) => IO (IV k)
getIVIO = do
	let p = Proxy
	    getTypedIV :: BlockCipher k => Proxy k -> IO (IV k)
	    getTypedIV pr = liftM IV (getEntropy (proxy blockSize pr `div` 8))
	iv <- getTypedIV p
	return (iv `asProxyTypeOf` ivProxy p)
{-# INLINEABLE getIVIO #-}

ctrProxy :: Proxy k -> Proxy (Ctr k)
ctrProxy = reproxy

ivProxy :: Proxy k -> Proxy (IV k)
ivProxy = reproxy

deIVProxy :: Proxy (IV k) -> Proxy k
deIVProxy = reproxy

proxyOf :: a -> Proxy a
proxyOf = const Proxy

ivBlockSizeBytes :: BlockCipher k => IV k -> Int
ivBlockSizeBytes iv =
	let p = deIVProxy (proxyOf iv)
	in proxy blockSize p `div` 8
{-# INLINEABLE ivBlockSizeBytes #-}

instance (BlockCipher k) => Serialize (IV k) where
	get = do
		let p = Proxy
		    doGet :: BlockCipher k => Proxy k -> Get (IV k)
	            doGet pr = liftM IV (SG.getByteString (proxy blockSizeBytes pr))
		iv <- doGet p
		return (iv `asProxyTypeOf` ivProxy p)
	put (IV iv) = SP.putByteString iv

instance (BlockCipher k) => Serialize (Ctr k) where
	get = do
		let p = Proxy
		    doGet :: BlockCipher k => Proxy k -> Get (Ctr k)
		    doGet pr = liftM (Ctr . bs2i) (SG.getByteString (proxy blockSizeBytes pr))
		cnt <- doGet p
		return (cnt `asProxyTypeOf` ctrProxy p)
	put c = do
		let p = Proxy
		    doPut :: BlockCipher k => Proxy k -> Ctr k -> Put
		    doPut pr c = SP.putByteString (i2bs (proxy blockSizeBytes pr) (unCtr c))
		doPut p (c `asProxyTypeOf` ctrProxy p)

-- TODO: GCM, GMAC
-- Consider the AES-only modes of XTS, CCM
