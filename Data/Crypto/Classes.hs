{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Data.Crypto.Classes
	( Hash(..)
	, Cipher(..)
	, for
	, (.::.)
	, hashFunc
	) where

import Data.Binary
import Data.Serialize
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as I
import Data.List (foldl')
import Data.Tagged
import Data.Crypto.Types

{-
class (Binary d, Serialize d)
    => Hash ctx d | d -> ctx, ctx -> d where
  outputLength	:: Tagged d BitLength
  blockLength	:: Tagged d BitLength
  hash		:: ByteString -> d
  initialCtx	:: ctx
  updateCtx	:: ctx -> ByteString -> ctx
  finalize	:: ctx -> d
  strength	:: Tagged d Int
-}

class (Binary d, Serialize d)
    => Hash ctx d | d -> ctx, ctx -> d where
  outputLength	:: Tagged d BitLength
  blockLength	:: Tagged d BitLength
  initialCtx	:: ctx
  updateCtx	:: ctx -> B.ByteString -> ctx
  finalize	:: ctx -> B.ByteString -> d
  strength	:: Tagged d Int
  needAlignment :: Tagged d Int
  hash :: L.ByteString -> d
  hash msg = res
    where
    res = finalize ctx end
    ctx = foldl' updateCtx initialCtx blks
    (blks,end) = makeBlocks msg blockLen (needAlignment .::. res)
    blockLen = (blockLength .::. res) `div` 8
  hash' :: B.ByteString -> d
  hash' msg = res
    where
    res = finalize (foldl' updateCtx initialCtx blks) end
    (blks, end) = makeBlocks (L.fromChunks [msg]) (blockLength .::. res `div` 8) (needAlignment .::. res)
  hashFunc :: Hash c d => d -> (L.ByteString -> d)
  hashFunc d = f
    where
    f = hash
    a = f undefined `asTypeOf` d

{-# INLINE makeBlocks #-}
makeBlocks :: L.ByteString -> ByteLength -> Int -> ([B.ByteString], B.ByteString)
makeBlocks msg len ali = go msg
  where
  go lps = 
	if B.length blk' == len
		then let (rest,end) = go lps in (blk':rest, end)
		else ([],blk)
    where
    blk = if isAligned blk' then blk' else B.copy blk'
    blk' = B.concat $ L.toChunks top
    (top,rest) = L.splitAt (fromIntegral len) lps
    isAligned (I.PS _ off _) = off `rem` ali == 0

for :: Tagged a b -> a -> b
for t _ = unTagged t

(.::.) :: Tagged a b -> a -> b
(.::.) = for


class Cipher k where
  blockSize	 :: Tagged k BitLength
  encrypt	 :: k -> B.ByteString -> B.ByteString
  decrypt	 :: k -> B.ByteString -> B.ByteString
  buildKey	 :: B.ByteString -> Maybe k
  keyLength	 :: k -> BitLength	-- ^ keyLength may inspect its argument to return the length
