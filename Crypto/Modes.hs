{-# LANGUAGE CPP #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 
 Authors: Thomas DuBuisson


 Generic mode implementations useable by any correct BlockCipher
 instance Be aware there are no tests for CFB mode yet.  See
 'Test.Crypto'.
-}
module Crypto.Modes (
        -- * Initialization Vector Type, Modifiers (for all ciphers, all modes that use IVs)
          getIV, getIVIO, zeroIV
        , dblIV
        -- * Blockcipher modes for lazy bytestrings. Versions for strict bytestrings are in 'Crypto.Classes'.
        , Crypto.Modes.ecb, Crypto.Modes.unEcb
        , Crypto.Modes.cbc, Crypto.Modes.unCbc
        , Crypto.Modes.cfb, Crypto.Modes.unCfb
        , Crypto.Modes.ofb, Crypto.Modes.unOfb
        , Crypto.Modes.ctr, Crypto.Modes.unCtr
        , siv, unSiv, siv', unSiv'
        -- * Authentication modes
        , cbcMac', cbcMac, cMac, cMac' 
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
import Data.Bits (xor, shift, (.&.), (.|.), testBit, setBit, clearBit, Bits, complementBit)
import Data.Tagged
import Crypto.Classes (BlockCipher(..), for, blockSizeBytes, incIV)
import Crypto.Random
import Crypto.Util
import Crypto.CPoly
import Crypto.Types
import System.Entropy (getEntropy)
import Control.Monad (liftM, forM_)
import Data.List (genericDrop)
import Data.Word (Word8)
import Data.List (genericDrop,genericReplicate,genericLength)

#if MIN_VERSION_tagged(0,2,0)
import Data.Proxy
#endif

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
-- 
-- This is written intentionally to take advantage
-- of the bytestring libraries 'zipWith'' rewrite rule but at the
-- extra cost of the resulting lazy bytestring being more fragmented
-- than either of the two inputs.
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

-- |Cipher block chaining message authentication
cbcMac' :: BlockCipher k => k -> B.ByteString -> B.ByteString
cbcMac' k pt = encode $ snd $ cbc' k zeroIV pt
{-# INLINEABLE cbcMac' #-}

-- |Cipher block chaining message authentication
cbcMac :: BlockCipher k => k -> L.ByteString -> L.ByteString
cbcMac k pt = L.fromChunks [encode $ snd $ Crypto.Modes.cbc k zeroIV pt]
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

-- |Counter mode for lazy bytestrings
ctr :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> L.ByteString -> (L.ByteString, IV k)
ctr = Crypto.Modes.unCtr

-- |Counter  mode for lazy bytestrings
unCtr :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> L.ByteString -> (L.ByteString, IV k)
unCtr f k (IV iv) msg =
       let ivStr = iterate f $ IV iv
           ivLen = fromIntegral $ B.length iv
           newIV = head $ genericDrop ((ivLen - 1 + L.length msg) `div` ivLen) ivStr
       in (zwp (L.fromChunks $ map (encryptBlock k) $ map initializationVector ivStr) msg, newIV)

-- |Generate cmac subkeys.  The usage of seq tries to force evaluation
-- of both keys avoiding posible timing attacks
cMacSubk :: BlockCipher k => k -> (IV k, IV k)
cMacSubk k = (k1, k2) `seq` (k1, k2)
  where
       bSize = blockSizeBytes `for` k
       k1 = dblIV $ IV $ encryptBlock k $ B.replicate bSize 0
       k2 = dblIV $ k1

-- |Pad the string as required by the cmac algorithm. In theory this
--  should work at bit level but since the API works at byte level we
--  do the same
cMacPad :: ([Word8], Bool, Int) -> Maybe (Word8,([Word8], Bool, Int))
cMacPad (_, _, 0) = Nothing
cMacPad ([], False, n) = Just (0,([], False, n-1))
cMacPad ([], True, n) = Just (128,([], False, n-1))
cMacPad (x:xs, b, n) =  Just (x,(xs, b, n-1))

-- |Obtain the cmac with the specified subkey for lazy bytestrings
cMacWithSubK :: BlockCipher k => k -> (IV k, IV k) -> L.ByteString -> L.ByteString
cMacWithSubK k (IV k1, IV k2) l = L.fromChunks $ [go (chunkFor k t) $ B.replicate bSize1 0]
  where
       bSize1 = fromIntegral $ blockSizeBytes `for` k
       bSize2 = fromIntegral $ blockSizeBytes `for` k
       (t,e) = L.splitAt (((L.length l-1)`div` bSize2)*bSize2) l
       pe =  fst $ B.unfoldrN (bSize1) cMacPad (L.unpack e,True,bSize1)
       fe | bSize2 == L.length e = zwp' k1 pe
          | otherwise =  zwp' k2 pe
       go [] c = encryptBlock k (zwp' c fe)
       go (x:xs) c = go xs $ encryptBlock k $ zwp' c x

-- |Obtain the cmac for lazy bytestrings
cMac :: BlockCipher k => k -> L.ByteString -> L.ByteString
cMac k = cMacWithSubK k (cMacSubk k)

-- |Obtain the cmac with the specified subkey for strict bytestrings
cMacWithSubK' :: BlockCipher k => k -> (IV k, IV k) -> B.ByteString -> B.ByteString
cMacWithSubK' k (IV k1, IV k2) b = go (chunkFor' k t) $ B.replicate bSize1 0
  where
       bSize1 = fromIntegral $ blockSizeBytes `for` k
       bSize2 = fromIntegral $ blockSizeBytes `for` k
       (t,e) = B.splitAt (((B.length b-1)`div` bSize2)*bSize2) b
       pe =  fst $ B.unfoldrN (bSize1) cMacPad (B.unpack e,True,bSize1)
       fe | bSize2 == B.length e = zwp' k1 pe
          | otherwise =  zwp' k2 pe
       go [] c = encryptBlock k (zwp' c fe)
       go (x:xs) c = go xs $ encryptBlock k $ zwp' c x

-- |Obtain the cmac for strict bytestrings
cMac' :: BlockCipher k => k -> B.ByteString -> B.ByteString
cMac' k = cMacWithSubK' k (cMacSubk k)

-- |Generate the xor stream for the last step of the CMAC* algorithm
xorend  :: Int -> (Int,[Word8]) -> Maybe (Word8,(Int,[Word8]))
xorend bsize (0, []) = Nothing
xorend bsize (n, x:xs) | n <= bsize = Just (x,((n-1),xs))
                       | otherwise = Just (0,((n-1),(x:xs)))

-- |Obtain the CMAC* on lazy bytestrings
cMacStar :: BlockCipher k => k -> [L.ByteString] -> L.ByteString
cMacStar k l = go (lcmac (L.replicate bSize 0)) l
  where
        bSize = fromIntegral $ blockSizeBytes `for` k
        bSizeb = fromIntegral $ blockSize `for` k
        lcmac = cMacWithSubK k (cMacSubk k)
        go s [] = s
        go s [x] | (L.length x) >= bSize = lcmac $ zwp x $ L.unfoldr (xorend $ fromIntegral bSize) (fromIntegral $ L.length x,L.unpack s)
                 | otherwise = lcmac $ zwp (dblL s) (L.unfoldr cMacPad (L.unpack x,True,fromIntegral bSize))
        go s (x:xs) = go (zwp (dblL s) (lcmac x)) xs

-- |Obtain the CMAC* on strict bytestrings
cMacStar' :: BlockCipher k => k -> [B.ByteString] -> B.ByteString
cMacStar' k s = go (lcmac (B.replicate bSize 0)) s
  where
       bSize = fromIntegral $ blockSizeBytes `for` k
       bSizeb = fromIntegral $ blockSize `for` k
       lcmac = cMacWithSubK' k (cMacSubk k)
       go s [] = s
       go s [x] | (B.length x) >= bSize = lcmac $ zwp' x $ fst $ B.unfoldrN (B.length x) (xorend bSize) (fromIntegral $ B.length x,B.unpack s)
                | otherwise = lcmac $ zwp' (dblB s) (fst $ B.unfoldrN bSize cMacPad (B.unpack x,True,bSize))
       go s (x:xs) = go (zwp' (dblB s) (lcmac x)) xs 

-- |Create the mask for SIV based ciphers
sivMask :: B.ByteString -> B.ByteString
sivMask b = snd $ B.mapAccumR (go) 0 b
  where
       go :: Int -> Word8 -> (Int,Word8)
       go 24 w = (32,clearBit w 7)
       go 56 w = (64,clearBit w 7)
       go n w = (n+8,w)

-- |SIV (Synthetic IV) mode for lazy bytestrings. First argument is
-- the optional list of bytestrings to be authenticated but not
-- encrypted As required by the specification this algorithm may
-- return nothing when certain constraints aren't met.
siv :: BlockCipher k => k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
siv k1 k2 xs m | length xs > bSizeb - 1 = Nothing
               | otherwise = Just $ L.append iv $ fst $ Crypto.Modes.ctr incIV k2 (IV $ sivMask $ B.concat $ L.toChunks iv) m
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       iv = cMacStar k1 $ xs ++ [m]


-- |SIV (Synthetic IV) for lazy bytestrings.  First argument is the
-- optional list of bytestrings to be authenticated but not encrypted.
-- As required by the specification this algorithm may return nothing
-- when authentication fails.
unSiv :: BlockCipher k => k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
unSiv k1 k2 xs c | length xs > bSizeb - 1 = Nothing
                 | L.length c < fromIntegral bSize = Nothing
                 | iv /= (cMacStar k1 $ xs ++ [dm]) = Nothing
                 | otherwise = Just dm
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       (iv,m) = L.splitAt (fromIntegral bSize) c
       dm = fst $ Crypto.Modes.unCtr incIV k2 (IV $ sivMask $ B.concat $ L.toChunks iv) m

-- |SIV (Synthetic IV) mode for strict bytestrings.  First argument is
-- the optional list of bytestrings to be authenticated but not
-- encrypted.  As required by the specification this algorithm may
-- return nothing when certain constraints aren't met.
siv' :: BlockCipher k => k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
siv' k1 k2 xs m | length xs > bSizeb - 1 = Nothing
                | otherwise = Just $ B.append iv $ fst $ Crypto.Classes.ctr k2 (IV $ sivMask iv) m
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       iv = cMacStar' k1 $ xs ++ [m]

-- |SIV (Synthetic IV) for strict bytestrings First argument is the
-- optional list of bytestrings to be authenticated but not encrypted
-- As required by the specification this algorithm may return nothing
-- when authentication fails.
unSiv' :: BlockCipher k => k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
unSiv' k1 k2 xs c | length xs > bSizeb - 1 = Nothing
                  | B.length c < bSize = Nothing
                  | iv /= (cMacStar' k1 $ xs ++ [dm]) = Nothing
                  | otherwise = Just dm
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       (iv,m) = B.splitAt bSize c
       dm = fst $ Crypto.Classes.unCtr k2 (IV $ sivMask iv) m

-- |Accumulator based double operation
dblw :: Bool -> (Int,[Int],Bool) -> Word8 -> ((Int,[Int],Bool), Word8)
dblw hb (i,xs,b) w = dblw' hb
  where
       slw True w = (setBit (shift w 1) 0)
       slw False w = (clearBit (shift w 1) 0)
       cpolyw i [] w = ((i+8,[]),w)
       cpolyw i (x:xs) w
         | x < i +8 = (\(a,b) -> (a,complementBit b (x-i))) $ cpolyw i xs w
         |otherwise = ((i+8,(x:xs)),w)
       b' = testBit w 7
       w' = slw b w
       ((i',xs'),w'') = cpolyw i xs w'
       dblw' False = i'`seq`xs'`seq`w''`seq`((i,xs,b'),w')
       dblw' True  = ((i',xs',b'),w'')

-- |Perform doubling as defined by the CMAC and SIV papers
dblIV :: BlockCipher k => IV k -> IV k
dblIV (IV b) = IV $ dblB b

-- |Perform doubling as defined by the CMAC and SIV papers
dblB :: B.ByteString -> B.ByteString
dblB b | B.null b = b
       | otherwise = snd $ B.mapAccumR (dblw (testBit (B.head b) 7)) (0,cpoly2revlist (B.length b * 8),False) b

-- |Perform doubling as defined by the CMAC and SIV papers
dblL :: L.ByteString -> L.ByteString
dblL b | L.null b = b
       | otherwise = snd $ L.mapAccumR (dblw (testBit (L.head b) 7)) (0,cpoly2revlist (L.length b * 8),False) b
 
-- |Cast a bigEndian ByteString into an Integer
decodeB :: B.ByteString -> Integer
decodeB = B.foldl' (\acc w -> (shift acc 8) + toInteger(w)) 0

-- |Cast an Integer into a bigEndian ByteString of size k.  It will
-- drop the MSBs in case the number is bigger than k and add 00s if it
-- is smaller.
encodeB :: (Ord a,Num a) => a -> Integer -> B.ByteString
encodeB k n = B.pack $ if lr > k then takel (lr - k) r else pad (k - lr) r
  where
       go 0 xs = xs 
       go n xs = go (shift n (-8)) (fromInteger (n .&. 255) : xs)
       pad 0 xs = xs
       pad n xs = 0 : pad (n-1) xs
       takel 0 xs = xs
       takel n (_:xs) = takel (n-1) xs
       r = go n []
       lr = genericLength r

-- |Cast a bigEndian ByteString into an Integer
decodeL :: L.ByteString -> Integer
decodeL = L.foldl' (\acc w -> (shift acc 8) + toInteger(w)) 0

-- |Cast an Integer into a bigEndian ByteString of size k.  It will
-- drop the MSBs in case the number is bigger than k and add 00s if it
-- is smaller.
encodeL :: (Ord a,Num a) => a -> Integer -> L.ByteString
encodeL k n = L.pack $ if lr > k then takel (lr - k) r else pad (k - lr) r
  where go 0 xs = xs 
        go n xs = go (shift n (-8)) (fromInteger (n .&. 255) : xs)
        pad 0 xs = xs
        pad n xs = 0 : pad (n-1) xs
        takel 0 xs = xs
        takel n (_:xs) = takel (n-1) xs
        r = go n []
        lr = genericLength r


-- |Obtain an `IV` made only of zeroes
zeroIV :: (BlockCipher k) => IV k
zeroIV = iv
  where bytes = ivBlockSizeBytes iv
        iv  = IV $ B.replicate  bytes 0

-- |Cook book mode - not really a mode at all.  If you don't know what you're doing, don't use this mode^H^H^H^H library.
ecb :: BlockCipher k => k -> L.ByteString -> L.ByteString
ecb k msg =
        let chunks = chunkFor k msg
        in L.fromChunks $ map (encryptBlock k) chunks
{-# INLINEABLE ecb #-}

-- |ECB decrypt, complementary to `ecb`.
unEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString
unEcb k msg =
        let chunks = chunkFor k msg
        in L.fromChunks $ map (decryptBlock k) chunks
{-# INLINEABLE unEcb #-}

-- | Like `ecb` but for strict bytestrings
ecb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
ecb' k msg =
        let chunks = chunkFor' k msg
        in B.concat $ map (encryptBlock k) chunks
{-# INLINEABLE ecb' #-}

-- |Decryption complement to `ecb'`
unEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
unEcb' k ct =
        let chunks = chunkFor' k ct
        in B.concat $ map (decryptBlock k) chunks
{-# INLINEABLE unEcb' #-}

-- |Ciphertext feed-back encryption mode for lazy bytestrings (with s
-- == blockSize)
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

-- |Ciphertext feed-back decryption mode for lazy bytestrings (with s
-- == blockSize)
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

-- |Ciphertext feed-back encryption mode for strict bytestrings (with
-- s == blockSize)
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
ofb = Crypto.Modes.unOfb
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
                        | B.length bs == bytes  -> Right (iv, g')
                        | otherwise             -> Left (GenErrorOther "Generator failed to provide requested number of bytes")
{-# INLINEABLE getIV #-}

-- | Obtain an 'IV' using the system entropy (see 'System.Crypto.Random')
getIVIO :: (BlockCipher k) => IO (IV k)
getIVIO = do
        let p = Proxy
            getTypedIV :: BlockCipher k => Proxy k -> IO (IV k)
            getTypedIV pr = liftM IV (getEntropy (proxy blockSize pr `div` 8))
        iv <- getTypedIV p
        return (iv `asProxyTypeOf` ivProxy p)
{-# INLINEABLE getIVIO #-}

ivProxy :: Proxy k -> Proxy (IV k)
ivProxy = const Proxy

deIVProxy :: Proxy (IV k) -> Proxy k
deIVProxy = const Proxy

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

-- TODO: GCM, GMAC
-- Consider the AES-only modes of XTS, CCM
