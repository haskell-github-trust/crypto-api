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
	( 
	-- * Hash class and helper functions
	  Hash(..)
	, hash
	, hash'
	, hashFunc
	, hashFunc'
	-- * Cipher classes and helper functions
	, BlockCipher(..)
	, blockSizeBytes
	, buildKeyIO
	, StreamCipher(..)
	, buildStreamKeyIO
	, AsymCipher(..)
	, buildKeyPairIO
	, Signing(..)
	, buildSigningKeyPairIO
	-- * Misc helper functions
	, for
	, (.::.)
	) where

import Data.Serialize
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as I
import Data.List (foldl')
import Data.Word (Word64)
import Data.Tagged
import Crypto.Types
import Crypto.Random
import System.Crypto.Random

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
  keyLength	:: Tagged k BitLength			-- ^ length of the cryptographic key

blockSizeBytes :: (BlockCipher k) => Tagged k ByteLength
blockSizeBytes = fmap (`div` 8) blockSize

buildKeyIO :: (BlockCipher k) -> IO k
buildKeyIO = go 0
  where
  go 1000 = error "Tried 1000 times to generate a key from the system entropy.\
                  \  No keys were returned! Perhaps the system entropy is broken\
                  \ or perhaps the BlockCipher instance being used has a non-flat\
                  \ keyspace."
  go i = do
	let bs = keyLength
	kd <- getEntropy ((7 + untag bs) `div` 8)
	case buildKey kd of
		Nothing -> go (i+1)
		Just k  -> return $ k `asTaggedTypeOf` bs

-- |Asymetric ciphers (common ones being RSA or EC based)
class (Serialize p, Serialize v) => AsymCipher p v where
  buildKeyPair :: CryptoRandomGen g => g -> BitLength -> Either GenError ((p,v),g) -- ^ build a public/private key pair using the provided generator
  encryptAsym      :: (CryptoRandomGen g) => g -> p -> B.ByteString -> Either GenError (B.ByteString,g)	-- ^ Asymetric encryption
  decryptAsym      :: v -> B.ByteString -> Maybe B.ByteString  -- ^ Asymetric decryption
  publicKeyLength  :: p -> BitLength
  privateKeyLength :: v -> BitLength

buildKeyPairIO :: AsymCipher p v => BitLength -> IO (Either GenError (p,v))
buildKeyPairIO bl = do
	g <- newGenIO :: IO SystemRandom
	case buildKeyPair g bl of
		Left err -> return (Left err)
		Right (k,_) -> return (Right k)

-- | A stream cipher class.  Instance are expected to work on messages as small as one byte
-- The length of the resulting cipher text should be equal
-- to the length of the input message.
class (Serialize k) => StreamCipher k iv | k -> iv where
  buildStreamKey	:: B.ByteString -> Maybe k
  encryptStream		:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  decryptStream 	:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  streamKeyLength	:: k -> BitLength

buildStreamKeyIO :: StreamCipher k iv => IO k
buildStreamKeyIO = go 0
  where
  go 1000 = error "Tried 1000 times to generate a stream key from the system entropy.\
                  \  No keys were returned! Perhaps the system entropy is broken\
                  \ or perhaps the BlockCipher instance being used has a non-flat\
                  \ keyspace."
  go i = do
	let bs = streamKeyLength
	kd <- getEntropy ((7 + untag bs) `div` 8)
	case buildStreamKey kd of
		Nothing -> go (i+1)
		Just k -> return $ k `asTaggedTypeOf` bs

-- | A class for signing operations which inherently can not be as generic
-- as asymetric ciphers (ex: DSA).
class (Serialize p, Serialize v) => Signing p v | p -> v, v -> p  where
  sign	 :: CryptoRandomGen g => g -> v -> L.ByteString -> Either GenError (B.ByteString, g)
  verify :: p -> L.ByteString -> B.ByteString -> Bool
  buildSigningPair :: CryptoRandomGen g => g -> BitLength -> Either GenError ((p, v), g)
  signingKeyLength :: v -> BitLength
  verifyingKeyLength :: p -> BitLength

buildSigningPairIO :: (Signing p v) => BitLength -> IO (Either GenError (p,v))
buildSigningPairIO bl = do
	g <- newGenIO :: IO SystemRandom
	case buildSigningPair g bl of
		Left err -> return $ Left err
		Right (k,_) -> return $ Right k
