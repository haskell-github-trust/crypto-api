{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Data.Crypto.Classes
	( Hash(..)
	, BlockCipher(..)
	, for
	, (.::.)
	, hash
	, hash'
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

-- |The Hash class is intended as the generic interface
-- targeted by maintainers of Haskell digest implementations.
-- Using this generic interface, higher level functions
-- such as 'hash' and 'hash'' provide a useful API
-- for comsumers of hash implementations.
class (Binary d, Serialize d)
    => Hash ctx d | d -> ctx, ctx -> d where
  outputLength	:: Tagged d BitLength	      -- ^ The size of the digest when encoded
  blockLength	:: Tagged d BitLength	      -- ^ The size of data operated on in each round of the digest computation
  initialCtx	:: ctx			      -- ^ An initial context, provided with the first call to 'updateCtx'
  updateCtx	:: ctx -> B.ByteString -> ctx -- ^ Used to update a context, repeatedly called until add data is exhausted
  finalize	:: ctx -> B.ByteString -> d   -- ^ Finializing a context, plus any message data less than the block size, into a digest
  strength	:: Tagged d BitLength	      -- ^ The believed cryptographic strength of the digest (computation time required to break)

hash :: (Hash ctx d) => L.ByteString -> d
hash msg = res
  where
  res = finalize ctx end
  ctx = foldl' updateCtx initialCtx blks
  (blks,end) = makeBlocks msg blockLen
  blockLen = (blockLength .::. res) `div` 8

hash' :: (Hash ctx d) => B.ByteString -> d
hash' msg = res
  where
  res = finalize (foldl' updateCtx initialCtx blks) end
  (blks, end) = makeBlocks (L.fromChunks [msg]) (blockLength .::. res `div` 8)

hashFunc :: Hash c d => d -> (L.ByteString -> d)
hashFunc d = f
  where
  f = hash
  a = f undefined `asTypeOf` d

{-# INLINE makeBlocks #-}
makeBlocks :: L.ByteString -> ByteLength -> ([B.ByteString], B.ByteString)
makeBlocks msg len = go msg
  where
  go lps = 
	if B.length blk == len
		then let (rest,end) = go lps in (blk:rest, end)
		else ([],blk)
    where
    blk = B.concat $ L.toChunks top
    (top,rest) = L.splitAt (fromIntegral len) lps

for :: Tagged a b -> a -> b
for t _ = unTagged t

(.::.) :: Tagged a b -> a -> b
(.::.) = for

class BlockCipher k where
  blockSize	:: Tagged k BitLength
  encryptBlock	:: k -> B.ByteString -> B.ByteString
  decryptBlock	:: k -> B.ByteString -> B.ByteString
  buildKey	:: B.ByteString -> Maybe k
  keyLength	:: k -> BitLength	-- ^ keyLength may inspect its argument to return the length
