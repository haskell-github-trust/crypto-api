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
	, buildKeyGen
	, StreamCipher(..)
	, buildStreamKeyIO
	, buildStreamKeyGen
	, AsymCipher(..)
	, buildKeyPairIO
	, buildKeyPairGen
	, Signing(..)
	, buildSigningKeyPairIO
	, buildSigningKeyPairGen
	-- * Misc helper functions
	, for
	, (.::.)
        , constTimeEq
        , encode
	) where

import Data.Serialize
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as I
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State (StateT(..), runStateT)
import Data.Bits ((.|.), xor)
import Data.List (foldl')
import Data.Word (Word64)
import Data.Tagged
import Crypto.Types
import Crypto.Random
import System.IO.Unsafe (unsafePerformIO)
import Foreign (Ptr)
import Foreign.C (CChar(..), CInt(..))
import System.Entropy

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

-- |Obtain a lazy hash function whose result is the same type
-- as the given digest, which is discarded.  If the type is already inferred then
-- consider using the 'hash' function instead.
hashFunc :: Hash c d => d -> (L.ByteString -> d)
hashFunc d = f
  where
  f = hash
  a = f undefined `asTypeOf` d

-- |Obtain a strict hash function whose result is the same type
-- as the given digest, which is discarded.  If the type is already inferred then
-- consider using the 'hash'' function instead.
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

-- |The number of bytes in a block cipher block
blockSizeBytes :: (BlockCipher k) => Tagged k ByteLength
blockSizeBytes = fmap (`div` 8) blockSize

-- |Build a symmetric key using the system entropy (see 'System.Crypto.Random')
buildKeyIO :: (BlockCipher k) => IO k
buildKeyIO = buildKeyM getEntropy fail

-- |Build a symmetric key using a given 'Crypto.Random.CryptoRandomGen'
buildKeyGen :: (BlockCipher k, CryptoRandomGen g) => g -> Either GenError (k, g)
buildKeyGen = runStateT (buildKeyM (StateT . genBytes) (lift . Left . GenErrorOther))

buildKeyM :: (BlockCipher k, Monad m) => (Int -> m B.ByteString) -> (String -> m k) -> m k
buildKeyM getMore err = go (0::Int)
  where
  go 1000 = err "Tried 1000 times to generate a key from the system entropy.\
                \  No keys were returned! Perhaps the system entropy is broken\
                \ or perhaps the BlockCipher instance being used has a non-flat\
                \ keyspace."
  go i = do
	let bs = keyLength
	kd <- getMore ((7 + untag bs) `div` 8)
	case buildKey kd of
		Nothing -> go (i+1)
		Just k  -> return $ k `asTaggedTypeOf` bs

-- |Asymetric ciphers (common ones being RSA or EC based)
class (Serialize p, Serialize v) => AsymCipher p v | p -> v, v -> p where
  buildKeyPair :: CryptoRandomGen g => g -> BitLength -> Either GenError ((p,v),g) -- ^ build a public/private key pair using the provided generator
  encryptAsym      :: (CryptoRandomGen g) => g -> p -> B.ByteString -> Either GenError (B.ByteString,g)	-- ^ Asymetric encryption
  decryptAsym      :: v -> B.ByteString -> Maybe B.ByteString  -- ^ Asymetric decryption
  publicKeyLength  :: p -> BitLength
  privateKeyLength :: v -> BitLength

-- |Build a pair of asymmetric keys using the system random generator.
buildKeyPairIO :: AsymCipher p v => BitLength -> IO (Either GenError (p,v))
buildKeyPairIO bl = do
	g <- newGenIO :: IO SystemRandom
	case buildKeyPair g bl of
		Left err -> return (Left err)
		Right (k,_) -> return (Right k)

-- |Flipped 'buildKeyPair' for ease of use with state monads.
buildKeyPairGen :: (CryptoRandomGen g, AsymCipher p v) => BitLength -> g -> Either GenError ((p,v),g)
buildKeyPairGen = flip buildKeyPair

-- | A stream cipher class.  Instance are expected to work on messages as small as one byte
-- The length of the resulting cipher text should be equal
-- to the length of the input message.
class (Serialize k) => StreamCipher k iv | k -> iv where
  buildStreamKey	:: B.ByteString -> Maybe k
  encryptStream		:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  decryptStream 	:: k -> iv -> B.ByteString -> (B.ByteString, iv)
  streamKeyLength	:: Tagged k BitLength

-- |Build a stream key using the system random generator
buildStreamKeyIO :: StreamCipher k iv => IO k
buildStreamKeyIO = buildStreamKeyM getEntropy fail

-- |Build a stream key using the provided random generator
buildStreamKeyGen :: (StreamCipher k iv, CryptoRandomGen g) => g -> Either GenError (k, g)
buildStreamKeyGen = runStateT (buildStreamKeyM (StateT . genBytes) (lift . Left . GenErrorOther))

buildStreamKeyM :: (Monad m, StreamCipher k iv) => (Int -> m B.ByteString) -> (String -> m k) -> m k
buildStreamKeyM getMore err = go (0::Int)
  where
  go 1000 = err "Tried 1000 times to generate a stream key from the system entropy.\
                \  No keys were returned! Perhaps the system entropy is broken\
                \ or perhaps the BlockCipher instance being used has a non-flat\
                \ keyspace."
  go i = do
	let k = streamKeyLength
	kd <- getMore ((untag k + 7) `div` 8)
	case buildStreamKey kd of
		Nothing -> go (i+1)
		Just k' -> return $ k' `asTaggedTypeOf` k

-- | A class for signing operations which inherently can not be as generic
-- as asymetric ciphers (ex: DSA).
class (Serialize p, Serialize v) => Signing p v | p -> v, v -> p  where
  sign	 :: CryptoRandomGen g => g -> v -> L.ByteString -> Either GenError (B.ByteString, g)
  verify :: p -> L.ByteString -> B.ByteString -> Bool
  buildSigningPair :: CryptoRandomGen g => g -> BitLength -> Either GenError ((p, v), g)
  signingKeyLength :: v -> BitLength
  verifyingKeyLength :: p -> BitLength

-- |Build a signing key using the system random generator
buildSigningKeyPairIO :: (Signing p v) => BitLength -> IO (Either GenError (p,v))
buildSigningKeyPairIO bl = do
	g <- newGenIO :: IO SystemRandom
	case buildSigningPair g bl of
		Left err -> return $ Left err
		Right (k,_) -> return $ Right k

-- |Flipped 'buildSigningPair' for ease of use with state monads.
buildSigningKeyPairGen :: (Signing p v, CryptoRandomGen g) => BitLength -> g -> Either GenError ((p, v), g)
buildSigningKeyPairGen = flip buildSigningPair

-- |Obtain a tagged value for a given type
for :: Tagged a b -> a -> b
for t _ = unTagged t

-- |Infix `for` operator
(.::.) :: Tagged a b -> a -> b
(.::.) = for

-- | Checks two bytestrings for equality without breaches for
-- timing attacks.
--
-- Semantically, @constTimeEq = (==)@.  However, @x == y@ takes less
-- time when the first byte is different than when the first byte
-- is equal.  This side channel allows an attacker to mount a
-- timing attack.  On the other hand, @constTimeEq@ always takes the
-- same time regardless of the bytestrings' contents, unless they are
-- of difference size.
--
-- You should always use @constTimeEq@ when comparing secrets,
-- otherwise you may leave a significant security hole
-- (cf. <http://codahale.com/a-lesson-in-timing-attacks/>).
constTimeEq :: B.ByteString -> B.ByteString -> Bool
constTimeEq s1 s2 =
    unsafePerformIO $
    unsafeUseAsCStringLen s1 $ \(s1_ptr, s1_len) ->
    unsafeUseAsCStringLen s2 $ \(s2_ptr, s2_len) ->
    if s1_len /= s2_len
      then return False
      else (== 0) `fmap` c_constTimeEq s1_ptr s2_ptr (fromIntegral s1_len)

foreign import ccall unsafe
   c_constTimeEq :: Ptr CChar -> Ptr CChar -> CInt -> IO CInt
