{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 

This is the heart of the crypto-api package.  By making (or having) 
an instance of Hash, AsymCipher, BlockCipher or StreamCipher you provide (or obtain)
access to any infrastructure built on these primitives include block cipher modes
of operation, hashing, hmac, signing, etc.  These classes allow users to build
routines that are agnostic to the algorithm used so changing algorithms is as simple
as changing a type signature.
-}

module Crypto.Classes
	( Hash(..)
	, BlockCipher(..)
	, blockSizeBytes
	, StreamCipher(..)
	, AsymCipher(..)
	, for
	, (.::.)
	, hash
	, hash'
	, hashFunc
	, hashFunc'
	) where

import Data.Serialize
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as I
import Data.List (foldl')
import Data.Tagged
import Crypto.Types
import Crypto.Random

-- |The Hash class is intended as the generic interface
-- targeted by maintainers of Haskell digest implementations.
-- Using this generic interface, higher level functions
-- such as 'hash' and 'hash'' provide a useful API
-- for comsumers of hash implementations.
--
-- Any instantiated implementation must handle unaligned data
class (Serialize d, Eq d, Ord d)
    => Hash ctx d | d -> ctx, ctx -> d where
  outputLength	:: Tagged d BitLength	      -- ^ The size of the digest when encoded
  blockLength	:: Tagged d BitLength	      -- ^ The amount of data operated on in each round of the digest computation
  initialCtx	:: ctx			      -- ^ An initial context, provided with the first call to 'updateCtx'
  updateCtx	:: ctx -> B.ByteString -> ctx -- ^ Used to update a context, repeatedly called until all data is exhausted
                                              --   must operate correctly for imputs of @n*blockLength@ bytes for @n `elem` [0..]@
  finalize	:: ctx -> B.ByteString -> d   -- ^ Finializing a context, plus any message data less than the block size, into a digest

-- |Hash a lazy ByteString, creating a digest
hash :: (Hash ctx d) => L.ByteString -> d
hash msg = res
  where
  res = finalize ctx end
  ctx = foldl' updateCtx initialCtx blks
  (blks,end) = makeBlocks msg blockLen
  blockLen = (blockLength .::. res) `div` 8

-- |Hash a strict ByteString, creating a digest
hash' :: (Hash ctx d) => B.ByteString -> d
hash' msg = res
  where
  res = finalize (updateCtx initialCtx top) end
  (top, end) = B.splitAt remlen msg
  remlen = B.length msg - (B.length msg `rem` bLen)
  bLen = blockLength `for` res `div` 8

-- |Obtain a lazy hash function from a digest
hashFunc :: Hash c d => d -> (L.ByteString -> d)
hashFunc d = f
  where
  f = hash
  a = f undefined `asTypeOf` d

-- |Obtain a strict hash function from a digest
hashFunc' :: Hash c d => d -> (B.ByteString -> d)
hashFunc' d = f
  where
  f = hash'
  a = f undefined `asTypeOf` d

{-# INLINE makeBlocks #-}
makeBlocks :: L.ByteString -> ByteLength -> ([B.ByteString], B.ByteString)
makeBlocks msg len = go (L.toChunks msg)
  where
  go [] = ([],B.empty)
  go (x:xs)
    | B.length x >= len =
	let l = B.length x - B.length x `rem` len
	    (top,end) = B.splitAt l x
	    (rest,trueEnd) = go (end:xs)
	in (top:rest, trueEnd)
    | otherwise =
	case xs of
		[] -> ([], x)
		(a:as) -> go (B.append x a : as)

-- |Obtain a tagged value for a given type
for :: Tagged a b -> a -> b
for t _ = unTagged t

-- |Infix `for` operator
(.::.) :: Tagged a b -> a -> b
(.::.) = for

-- |The BlockCipher class is intended as the generic interface
-- targeted by maintainers of Haskell cipher implementations.
-- Using this generic interface higher level functions
-- such as 'cbc', and other functions from Data.Crypto.Modes, provide a useful API
-- for comsumers of cipher implementations.
--
-- Instances must handle unaligned data
class ( Serialize k) => BlockCipher k where
  blockSize	:: Tagged k BitLength			-- ^ The size of a single block; the smallest unit on which the cipher operates.
  encryptBlock	:: k -> B.ByteString -> B.ByteString	-- ^ encrypt data of size @n*blockSize@ where @n `elem` [0..]@  (ecb encryption)
  decryptBlock	:: k -> B.ByteString -> B.ByteString	-- ^ decrypt data of size @n*blockSize@ where @n `elem` [0..]@  (ecb decryption)
  buildKey	:: B.ByteString -> Maybe k		-- ^ smart constructor for keys from a bytestring.
  keyLength	:: k -> BitLength			-- ^ keyLength may inspect its argument to return the length

blockSizeBytes :: (BlockCipher k) => Tagged k ByteLength
blockSizeBytes = fmap (`div` 8) blockSize

class (Serialize p) => AsymCipher p where
  buildKeyPair :: CryptoRandomGen g => g -> BitLength -> Maybe ((p,p),g) -- ^ build a public/private key pair using the provided generator
  encryptAsym     :: p -> B.ByteString -> B.ByteString	-- ^ Asymetric encryption
  decryptAsym     :: p -> B.ByteString -> B.ByteString  -- ^ Asymetric decryption
  asymKeyLength   :: p -> BitLength

-- | `signUsing d k msg` Returns a signature (not a message + signature) for `msg`
-- by hashing into a digest asTypeOf `d` and encrypting using the asymetric key `k`.
--
-- Expect a "Signature" class to appear in a future crypto-api
-- (this function might become depricated pending discussion)
signUsing :: (Hash c d, AsymCipher p) => d -> p -> L.ByteString -> B.ByteString
signUsing d p = encryptAsym p . Data.Serialize.encode . hashFunc d

-- | Like `signUsing` but for strict ByteStrings.
signUsing' :: (Hash c d, AsymCipher p) => d -> p -> B.ByteString -> B.ByteString
signUsing' d p = encryptAsym p . Data.Serialize.encode . hashFunc' d

-- | A stream cipher class.  Instance are expected to work on messages as small as one byte
-- The length of the resulting cipher text should be equal
-- to the length of the input message.
class (Serialize k) => StreamCipher k iv | k -> iv where
  buildStreamKey	:: B.ByteString -> Maybe k
  encryptStream		:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  decryptStream 	:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  streamKeyLength	:: k -> BitLength
