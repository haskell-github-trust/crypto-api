{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
{-# LANGUAGE ParallelListComp #-}
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
        , hashFunc'
        , hashFunc
        -- * Cipher classes and helper functions
        , BlockCipher(..)
        , blockSizeBytes
        , keyLengthBytes
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
        , encode
        , zeroIV
        , incIV
        , getIV, getIVIO
        , chunkFor, chunkFor'
        , module Crypto.Util
        , module Crypto.Types
        ) where

import Data.Data
import Data.Typeable
import Data.Serialize
import qualified Data.Serialize.Get as SG
import qualified Data.Serialize.Put as SP
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as I
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.State (StateT(..), runStateT)
import Control.Monad (liftM)
import Data.Bits
import Data.List (foldl', genericDrop)
import Data.Word (Word8, Word16, Word64)
import Data.Tagged
import Data.Proxy
import Crypto.Types
import Crypto.Random
import Crypto.Util
import System.IO.Unsafe (unsafePerformIO)
import Foreign (Ptr)
import Foreign.C (CChar(..), CInt(..))
import System.Entropy
import {-# SOURCE #-} Crypto.Modes

-- |The Hash class is intended as the generic interface
-- targeted by maintainers of Haskell digest implementations.
-- Using this generic interface, higher level functions
-- such as 'hash' and 'hash'' provide a useful API
-- for comsumers of hash implementations.
--
-- Any instantiated implementation must handle unaligned data.
--
-- Minimum complete definition: 'outputLength', 'blockLength', 'initialCtx',
-- 'updateCtx', and 'finalize'.
class (Serialize d, Eq d, Ord d)
    => Hash ctx d | d -> ctx, ctx -> d where
  outputLength  :: Tagged d BitLength         -- ^ The size of the digest when encoded
  blockLength   :: Tagged d BitLength         -- ^ The amount of data operated on in each round of the digest computation
  initialCtx    :: ctx                        -- ^ An initial context, provided with the first call to 'updateCtx'
  updateCtx     :: ctx -> B.ByteString -> ctx -- ^ Used to update a context, repeatedly called until all data is exhausted
                                              --   must operate correctly for imputs of @n*blockLength@ bytes for @n `elem` [0..]@
  finalize      :: ctx -> B.ByteString -> d   -- ^ Finializing a context, plus any message data less than the block size, into a digest

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

{-# INLINABLE makeBlocks #-}
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
--
-- Minimum complete definition: blockSize, encryptBlock, decryptBlock,
-- buildKey, and keyLength.
--
-- Instances must handle unaligned data
class ( Serialize k) => BlockCipher k where
  blockSize     :: Tagged k BitLength                   -- ^ The size of a single block; the smallest unit on which the cipher operates.
  encryptBlock  :: k -> B.ByteString -> B.ByteString    -- ^ encrypt data of size @n*blockSize@ where @n `elem` [0..]@  (ecb encryption)
  decryptBlock  :: k -> B.ByteString -> B.ByteString    -- ^ decrypt data of size @n*blockSize@ where @n `elem` [0..]@  (ecb decryption)
  buildKey      :: B.ByteString -> Maybe k              -- ^ smart constructor for keys from a bytestring.
  keyLength     :: Tagged k BitLength                   -- ^ length of the cryptographic key

  -- * Modes of operation over strict bytestrings
  -- | Electronic Cookbook (encryption)
  ecb           :: k -> B.ByteString -> B.ByteString
  ecb = modeEcb'
  -- | Electronic Cookbook (decryption)
  unEcb         :: k -> B.ByteString -> B.ByteString
  unEcb = modeUnEcb'
  -- | Cipherblock Chaining (encryption)
  cbc           :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  cbc = modeCbc'
  -- | Cipherblock Chaining (decryption)
  unCbc         :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  unCbc = modeUnCbc'

  -- | Counter (encryption)
  ctr           :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  ctr = modeCtr' incIV

  -- | Counter (decryption)
  unCtr         :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  unCtr = modeUnCtr' incIV

  -- | Counter (encryption)
  ctrLazy           :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  ctrLazy = modeCtr incIV

  -- | Counter (decryption)
  unCtrLazy         :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  unCtrLazy = modeUnCtr incIV

  -- | Ciphertext feedback (encryption)
  cfb           :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  cfb = modeCfb'
  -- | Ciphertext feedback (decryption)
  unCfb         :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  unCfb = modeUnCfb'
  -- | Output feedback (encryption)
  ofb           :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  ofb = modeOfb'

  -- | Output feedback (decryption)
  unOfb         :: k -> IV k -> B.ByteString -> (B.ByteString, IV k)
  unOfb = modeUnOfb'

  -- |Cipher block chaining encryption for lazy bytestrings
  cbcLazy       :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  cbcLazy = modeCbc

  -- |Cipher block chaining decryption for lazy bytestrings
  unCbcLazy     :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  unCbcLazy = modeUnCbc

  -- |SIV (Synthetic IV) mode for lazy bytestrings. The third argument is
  -- the optional list of bytestrings to be authenticated but not
  -- encrypted As required by the specification this algorithm may
  -- return nothing when certain constraints aren't met.
  sivLazy :: k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
  sivLazy = modeSiv

  -- |SIV (Synthetic IV) for lazy bytestrings.  The third argument is the
  -- optional list of bytestrings to be authenticated but not encrypted.
  -- As required by the specification this algorithm may return nothing
  -- when authentication fails.
  unSivLazy :: k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
  unSivLazy = modeUnSiv

  -- |SIV (Synthetic IV) mode for strict bytestrings.  First argument is
  -- the optional list of bytestrings to be authenticated but not
  -- encrypted.  As required by the specification this algorithm may
  -- return nothing when certain constraints aren't met.
  siv :: k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
  siv = modeSiv'

  -- |SIV (Synthetic IV) for strict bytestrings First argument is the
  -- optional list of bytestrings to be authenticated but not encrypted
  -- As required by the specification this algorithm may return nothing
  -- when authentication fails.
  unSiv :: k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
  unSiv = modeUnSiv'

  -- |Cook book mode - not really a mode at all.  If you don't know what you're doing, don't use this mode^H^H^H^H library.
  ecbLazy :: k -> L.ByteString -> L.ByteString
  ecbLazy = modeEcb

  -- |ECB decrypt, complementary to `ecb`.
  unEcbLazy :: k -> L.ByteString -> L.ByteString
  unEcbLazy = modeUnEcb

  -- |Ciphertext feed-back encryption mode for lazy bytestrings (with s
  -- == blockSize)
  cfbLazy :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  cfbLazy = modeCfb

  -- |Ciphertext feed-back decryption mode for lazy bytestrings (with s
  -- == blockSize)
  unCfbLazy :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  unCfbLazy = modeUnCfb

  -- |Output feedback mode for lazy bytestrings
  ofbLazy  :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  ofbLazy = modeOfb

  -- |Output feedback mode for lazy bytestrings
  unOfbLazy :: k -> IV k -> L.ByteString -> (L.ByteString, IV k)
  unOfbLazy = modeUnOfb

  -- |CWC mode, returning.  @cwc k iv aad pt == (ct,tag)@.  That is cwc
  -- is an authenticating encryption mode that takes the key, initilization
  -- vector, additional authenticated data, and plaintext as input.  The
  -- result is ciphertext and a authentication tag.
  cwc :: k -> IV k -> B.ByteString -> B.ByteString -> Either BlockCipherError (B.ByteString,B.ByteString)
  cwc = modeCwc'

  -- |@unCwc k iv aad ct tag@ authenticates and decrypts data encrypted
  -- using CWC mode.  Authentication failure result in @Nothing@.
  unCwc :: k -> IV k -> B.ByteString -> B.ByteString -> B.ByteString -> Either BlockCipherError B.ByteString
  unCwc = modeUnCwc'

-- |Output feedback mode for lazy bytestrings
modeOfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeOfb = modeUnOfb
{-# INLINEABLE modeOfb #-}

-- |Output feedback mode for lazy bytestrings
modeUnOfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeUnOfb k (IV iv) msg =
        let ivStr = drop 1 (iterate (encryptBlock k) iv)
            ivLen = fromIntegral (B.length iv)
            newIV = IV . B.concat . L.toChunks . L.take ivLen . L.drop (L.length msg) . L.fromChunks $ ivStr
        in (zwp (L.fromChunks ivStr) msg, newIV)
{-# INLINEABLE modeUnOfb #-}


-- |Ciphertext feed-back encryption mode for lazy bytestrings (with s
-- == blockSize)
modeCfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeCfb k (IV v) msg =
        let blks = chunkFor k msg
            (cs,ivF) = go v blks
        in (L.fromChunks cs, IV ivF)
  where
  go iv [] = ([],iv)
  go iv (b:bs) =
        let c = zwp' (encryptBlock k iv) b
            (cs,ivFinal) = go c bs
        in (c:cs, ivFinal)
{-# INLINEABLE modeCfb #-}

-- |Ciphertext feed-back decryption mode for lazy bytestrings (with s
-- == blockSize)
modeUnCfb :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeUnCfb k (IV v) msg = 
        let blks = chunkFor k msg
            (ps, ivF) = go v blks
        in (L.fromChunks ps, IV ivF)
  where
  go iv [] = ([], iv)
  go iv (b:bs) =
        let p = zwp' (encryptBlock k iv) b
            (ps, ivF) = go b bs
        in (p:ps, ivF)
{-# INLINEABLE modeUnCfb #-}

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

-- |Cook book mode - not really a mode at all.  If you don't know what you're doing, don't use this mode^H^H^H^H library.
modeEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString
modeEcb k msg =
        let chunks = chunkFor k msg
        in L.fromChunks $ map (encryptBlock k) chunks
{-# INLINEABLE modeEcb #-}

-- |ECB decrypt, complementary to `ecb`.
modeUnEcb :: BlockCipher k => k -> L.ByteString -> L.ByteString
modeUnEcb k msg =
        let chunks = chunkFor k msg
        in L.fromChunks $ map (decryptBlock k) chunks
{-# INLINEABLE modeUnEcb #-}

-- |SIV (Synthetic IV) mode for lazy bytestrings. The third argument is
-- the optional list of bytestrings to be authenticated but not
-- encrypted As required by the specification this algorithm may
-- return nothing when certain constraints aren't met.
modeSiv :: BlockCipher k => k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
modeSiv k1 k2 xs m
    | length xs > bSizeb - 1 = Nothing
    | otherwise = Just
                . L.append iv
                . fst
                . ctrLazy k2 (IV . sivMask . B.concat . L.toChunks $ iv)
                $ m
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       iv = cMacStar k1 $ xs ++ [m]


-- |SIV (Synthetic IV) for lazy bytestrings.  The third argument is the
-- optional list of bytestrings to be authenticated but not encrypted.
-- As required by the specification this algorithm may return nothing
-- when authentication fails.
modeUnSiv :: BlockCipher k => k -> k -> [L.ByteString] -> L.ByteString -> Maybe L.ByteString
modeUnSiv k1 k2 xs c | length xs > bSizeb - 1 = Nothing
                 | L.length c < fromIntegral bSize = Nothing
                 | iv /= (cMacStar k1 $ xs ++ [dm]) = Nothing
                 | otherwise = Just dm
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       (iv,m) = L.splitAt (fromIntegral bSize) c
       dm = fst $ modeUnCtr incIV k2 (IV $ sivMask $ B.concat $ L.toChunks iv) m

-- |SIV (Synthetic IV) mode for strict bytestrings.  First argument is
-- the optional list of bytestrings to be authenticated but not
-- encrypted.  As required by the specification this algorithm may
-- return nothing when certain constraints aren't met.
modeSiv' :: BlockCipher k => k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
modeSiv' k1 k2 xs m | length xs > bSizeb - 1 = Nothing
                | otherwise = Just $ B.append iv $ fst $ Crypto.Classes.ctr k2 (IV $ sivMask iv) m
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       iv = cMacStar' k1 $ xs ++ [m]

-- |SIV (Synthetic IV) for strict bytestrings First argument is the
-- optional list of bytestrings to be authenticated but not encrypted
-- As required by the specification this algorithm may return nothing
-- when authentication fails.
modeUnSiv' :: BlockCipher k => k -> k -> [B.ByteString] -> B.ByteString -> Maybe B.ByteString
modeUnSiv' k1 k2 xs c | length xs > bSizeb - 1 = Nothing
                  | B.length c < bSize = Nothing
                  | iv /= (cMacStar' k1 $ xs ++ [dm]) = Nothing
                  | otherwise = Just dm
  where
       bSize = fromIntegral $ blockSizeBytes `for` k1
       bSizeb = fromIntegral $ blockSize `for` k1
       (iv,m) = B.splitAt bSize c
       dm = fst $ Crypto.Classes.unCtr k2 (IV $ sivMask iv) m


modeCbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeCbc k (IV v) plaintext =
        let blks = chunkFor k plaintext
            (cts, iv) = go blks v
        in (L.fromChunks cts, IV iv)
  where
  go [] iv = ([], iv)
  go (b:bs) iv =
        let c = encryptBlock k (zwp' iv b)
            (cs, ivFinal) = go bs c
        in (c:cs, ivFinal)
{-# INLINEABLE modeCbc #-}

modeUnCbc :: BlockCipher k => k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeUnCbc k (IV v) ciphertext =
        let blks = chunkFor k ciphertext
            (pts, iv) = go blks v
        in (L.fromChunks pts, IV iv)
  where
  go [] iv = ([], iv)
  go (c:cs) iv =
        let p = zwp' (decryptBlock k c) iv
            (ps, ivFinal) = go cs c
        in (p:ps, ivFinal)
{-# INLINEABLE modeUnCbc #-}

-- |Counter mode for lazy bytestrings
modeCtr :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeCtr = modeUnCtr

-- |Counter  mode for lazy bytestrings
modeUnCtr :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> L.ByteString -> (L.ByteString, IV k)
modeUnCtr f k (IV iv) msg =
       let ivStr = iterate f $ IV iv
           ivLen = fromIntegral $ B.length iv
           newIV = head $ genericDrop ((ivLen - 1 + L.length msg) `div` ivLen) ivStr
       in (zwp (L.fromChunks $ map (encryptBlock k) $ map initializationVector ivStr) msg, newIV)


-- |The number of bytes in a block cipher block
blockSizeBytes :: (BlockCipher k) => Tagged k ByteLength
blockSizeBytes = fmap (`div` 8) blockSize

-- |The number of bytes in a block cipher key (assuming it is an even
-- multiple of 8 bits)
keyLengthBytes :: (BlockCipher k) => Tagged k ByteLength
keyLengthBytes = fmap (`div` 8) keyLength

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
class AsymCipher p v | p -> v, v -> p where
  buildKeyPair :: CryptoRandomGen g => g -> BitLength -> Either GenError ((p,v),g) -- ^ build a public/private key pair using the provided generator
  encryptAsym      :: (CryptoRandomGen g) => g -> p -> B.ByteString -> Either GenError (B.ByteString, g) -- ^ Asymetric encryption
  decryptAsym      :: (CryptoRandomGen g) => g -> v -> B.ByteString -> Either GenError (B.ByteString, g) -- ^ Asymetric decryption
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
  buildStreamKey        :: B.ByteString -> Maybe k
  encryptStream         :: k -> iv -> B.ByteString -> (B.ByteString, iv)
  decryptStream         :: k -> iv -> B.ByteString -> (B.ByteString, iv)
  streamKeyLength       :: Tagged k BitLength

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
  sign   :: CryptoRandomGen g => g -> v -> L.ByteString -> Either GenError (B.ByteString, g)
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

-- | Like `ecb` but for strict bytestrings
modeEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
modeEcb' k msg =
        let chunks = chunkFor' k msg
        in B.concat $ map (encryptBlock k) chunks
{-# INLINE modeEcb' #-}

-- |Decryption complement to `ecb'`
modeUnEcb' :: BlockCipher k => k -> B.ByteString -> B.ByteString
modeUnEcb' k ct =
        let chunks = chunkFor' k ct
        in B.concat $ map (decryptBlock k) chunks
{-# INLINE modeUnEcb' #-}

-- |Cipher block chaining encryption mode on strict bytestrings
modeCbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeCbc' k (IV v) plaintext =
        let blks = chunkFor' k plaintext
            (cts, iv) = go blks v
        in (B.concat cts, IV iv)
  where
  go [] iv = ([], iv)
  go (b:bs) iv =
        let c = encryptBlock k (zwp' iv b)
            (cs, ivFinal) = go bs c
        in (c:cs, ivFinal)
{-# INLINEABLE modeCbc' #-}

-- |Cipher block chaining decryption for strict bytestrings
modeUnCbc' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeUnCbc' k (IV v) ciphertext =
        let blks = chunkFor' k ciphertext
            (pts, iv) = go blks v
        in (B.concat pts, IV iv)
  where
  go [] iv = ([], iv)
  go (c:cs) iv =
        let p = zwp' (decryptBlock k c) iv
            (ps, ivFinal) = go cs c
        in (p:ps, ivFinal)
{-# INLINEABLE modeUnCbc' #-}

-- |Output feedback mode for strict bytestrings
modeOfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeOfb' = modeUnOfb'
{-# INLINEABLE modeOfb' #-}

-- |Output feedback mode for strict bytestrings
modeUnOfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeUnOfb' k (IV iv) msg =
        let ivStr = collect (B.length msg + ivLen) (drop 1 (iterate (encryptBlock k) iv))
            ivLen = B.length iv
            mLen = fromIntegral (B.length msg)
            newIV = IV . B.concat . L.toChunks . L.take (fromIntegral ivLen) . L.drop mLen . L.fromChunks $ ivStr
        in (zwp' (B.concat ivStr) msg, newIV)
{-# INLINEABLE modeUnOfb' #-}

-- |Counter mode for strict bytestrings
modeCtr' :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeCtr' = modeUnCtr'
{-# INLINEABLE modeCtr' #-}

-- |Counter mode for strict bytestrings
modeUnCtr' :: BlockCipher k => (IV k -> IV k) -> k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeUnCtr' f k iv msg =
       let fa (st,IV iv) c 
              | B.null st = fa (encryptBlock k iv, f (IV iv)) c
              | otherwise = let Just (s,nst) = B.uncons st in ((nst,IV iv),xor c s)
           ((_,newIV),res) = B.mapAccumL fa (B.empty,iv) msg 
       in (res,newIV)
{-# INLINEABLE modeUnCtr' #-}

-- |Ciphertext feed-back encryption mode for strict bytestrings (with
-- s == blockSize)
modeCfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeCfb' k (IV v) msg =
        let blks = chunkFor' k msg
            (cs,ivF) = go v blks
        in (B.concat cs, IV ivF)
  where
  go iv [] = ([],iv)
  go iv (b:bs) =
        let c = zwp' (encryptBlock k iv) b
            (cs,ivFinal) = go c bs
        in (c:cs, ivFinal)
{-# INLINEABLE modeCfb' #-}

-- |Ciphertext feed-back decryption mode for strict bytestrings (with s == blockSize)
modeUnCfb' :: BlockCipher k => k -> IV k -> B.ByteString -> (B.ByteString, IV k)
modeUnCfb' k (IV v) msg =
        let blks = chunkFor' k msg
            (ps, ivF) = go v blks
        in (B.concat ps, IV ivF)
  where
  go iv [] = ([], iv)
  go iv (b:bs) =
        let p = zwp' (encryptBlock k iv) b
            (ps, ivF) = go b bs
        in (p:ps, ivF)
{-# INLINEABLE modeUnCfb' #-}

-- | CWC mode
modeCwc' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString -> Either BlockCipherError (B.ByteString, B.ByteString)
modeCwc' k iv aad pt
   | genericLen aad > ccwAADSpace k = Left (InputTooLong "AAD too long to be authenticated CWC and given cipher")
   | genericLen pt  > ccwMsgSpace k = Left (InputTooLong "PT too long to be protected with CWC and given cipher")
   | otherwise                      = Right (ct,tag)
  where
    genericLen = fromIntegral . B.length
    ct  = cwc_ctr' k iv pt
    tag = cwc_mac' k iv aad ct

ccwAADSpace, ccwMsgSpace :: BlockCipher k => k -> Integer
ccwAADSpace k = fromIntegral (blockSizeBytes .::. k) * (2^32 - 1)
ccwMsgSpace k = fromIntegral (blockSizeBytes .::. k) * (2^32 - 1)

modeUnCwc' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString -> B.ByteString -> Either BlockCipherError B.ByteString
modeUnCwc' k iv aad ct tag 
  | invalidInput = Left $ InputTooLong "AAD or CT input was too long"
  | invalidTag   = Left $ AuthenticationFailed ""
  | otherwise    = Right pt
  where
    pt       = cwc_ctr' k iv ct

    invalidInput  = genericLen aad > ccwAADSpace k ||
                    genericLen ct  > ccwMsgSpace k
    invalidTag    =  not (constTimeEq computedTag tag)
    -- Notice the default implementation is to assume full tag sizes
    computedTag = B.take (B.length tag) $ cwc_mac' k iv aad ct
    genericLen  = fromIntegral . B.length

-- The IV should be of length blockSizeBytes - 5
cwc_ctr' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString
cwc_ctr' k (IV iv) input =
        let fullIV = B.concat [B.pack [0x80], iv, B.pack [0, 0, 0, 1]]
        in fst $ modeCtr' incIV k (IV fullIV) input

-- The IV should be of length blockSizeBytes - 5
cwc_mac' :: BlockCipher k => k -> IV k -> B.ByteString -> B.ByteString -> B.ByteString
cwc_mac' k (IV iv) aad ct =
    let fullIV = B.concat [B.pack [0x80], iv, B.replicate 4 0]
        r = modeEcb' k $ cwc_hash' k aad ct
    in zwp' r $ modeEcb' k fullIV

cwc_hash' :: BlockCipher k => k -> B.ByteString -> B.ByteString -> B.ByteString
cwc_hash' k aad ct =
    let z  = B.concat [ B.pack [0XC0], B.replicate ((blockSizeBytes .::. k) - 1) 0]
        kh = cwcMask . bs2i . modeEcb' k $ z                             :: Integer
        l  = cwcBlkSz - (B.length aad `rem` cwcBlkSz)
        l' = cwcBlkSz - (B.length ct  `rem` cwcBlkSz)
        x  = B.concat [ aad, B.replicate l 0, ct, B.replicate l' 0]
        b  = B.length x `div` 12
        ys = map bs2i $ toChunks 12 x                                   :: [Integer]
        yb1 = 2^64 * fromIntegral (B.length aad)                        :: Integer
    in i2bs 128 $ (yb1 + sum [ y * kh^i | y <- ys | i <- [b,b-1..1] ]) `rem` (2^127 - 1)
  where
      cwcMask = (.&.) (2^128 - 1)
      cwcBlkSz = 16

toChunks :: Int -> B.ByteString -> [B.ByteString]
toChunks n val = go val
  where
  go b
    | B.length b == 0 = []
    | otherwise       = let (h,t) = B.splitAt n b
                        in h : go t

-- |Increase an `IV` by one.  This is way faster than decoding,
-- increasing, encoding
incIV :: BlockCipher k => IV k -> IV k
incIV (IV b) = IV $ snd $ B.mapAccumR (incw) 1 b
  where
       incw :: Word16 -> Word8 -> (Word16, Word8)
       incw i w = let nw=i+(fromIntegral w) in (shiftR nw 8, fromIntegral nw)

-- |Obtain an `IV` made only of zeroes
zeroIV :: (BlockCipher k) => IV k
zeroIV = iv
  where bytes = ivBlockSizeBytes iv
        iv  = IV $ B.replicate  bytes 0

zeroIVcwc :: BlockCipher k => IV k
zeroIVcwc = iv
  where bytes = ivBlockSizeBytes iv - 5  -- a constant of cwc (4 bytes for ctr mode, 1 for a sort of header on the iv)
        iv    = IV $ B.replicate bytes 0

-- Break a bytestring into block size chunks.
chunkFor :: (BlockCipher k) => k -> L.ByteString -> [B.ByteString]
chunkFor k = go
  where
  blkSz = (blockSize `for` k) `div` 8
  blkSzI = fromIntegral blkSz
  go bs | L.length bs < blkSzI = []
        | otherwise            = let (blk,rest) = L.splitAt blkSzI bs in B.concat (L.toChunks blk) : go rest
{-# INLINE chunkFor #-}

-- Break a bytestring into block size chunks.
chunkFor' :: (BlockCipher k) => k -> B.ByteString -> [B.ByteString]
chunkFor' k = go
  where
  blkSz = (blockSize `for` k) `div` 8
  go bs | B.length bs < blkSz = []
        | otherwise           = let (blk,rest) = B.splitAt blkSz bs in blk : go rest
{-# INLINE chunkFor' #-}

-- |Create the mask for SIV based ciphers
sivMask :: B.ByteString -> B.ByteString
sivMask b = snd $ B.mapAccumR (go) 0 b
  where
       go :: Int -> Word8 -> (Int,Word8)
       go 24 w = (32,clearBit w 7)
       go 56 w = (64,clearBit w 7)
       go n w = (n+8,w)

ivBlockSizeBytes :: BlockCipher k => IV k -> Int
ivBlockSizeBytes iv =
        let p = deIVProxy (proxyOf iv)
        in proxy blockSize p `div` 8
 where
  proxyOf :: a -> Proxy a
  proxyOf = const Proxy
{-# INLINEABLE ivBlockSizeBytes #-}

instance (BlockCipher k) => Serialize (IV k) where
        get = do
                let p = Proxy
                    doGet :: BlockCipher k => Proxy k -> Get (IV k)
                    doGet pr = liftM IV (SG.getByteString (proxy blockSizeBytes pr))
                iv <- doGet p
                return (iv `asProxyTypeOf` ivProxy p)
        put (IV iv) = SP.putByteString iv

