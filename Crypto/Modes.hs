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
          dblIV
        -- * Authentication modes
        , cbcMac', cbcMac, cMac, cMac'
        , cMacStar, cMacStar'
        -- Combined modes (nothing here yet)
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
import Crypto.Classes (BlockCipher(..), for, blockSizeBytes, incIV, zeroIV, chunkFor, chunkFor')
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

-- |Cipher block chaining message authentication
cbcMac' :: BlockCipher k => k -> B.ByteString -> B.ByteString
cbcMac' k pt = encode $ snd $ cbc k zeroIV pt
{-# INLINEABLE cbcMac' #-}

-- |Cipher block chaining message authentication
cbcMac :: BlockCipher k => k -> L.ByteString -> L.ByteString
cbcMac k pt = L.fromChunks [encode $ snd $ cbcLazy k zeroIV pt]
{-# INLINEABLE cbcMac #-}

-- |Generate cmac subkeys.
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

-- |Generate the xor stream for the last step of the CMAC* algorithm
xorend  :: Int -> (Int,[Word8]) -> Maybe (Word8,(Int,[Word8]))
xorend bsize (0, []) = Nothing
xorend bsize (n, x:xs) | n <= bsize = Just (x,((n-1),xs))
                       | otherwise = Just (0,((n-1),(x:xs)))

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

-- TODO: GCM, GMAC
-- Consider the AES-only modes of XTS, CCM
