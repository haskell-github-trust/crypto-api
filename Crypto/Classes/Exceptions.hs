-- |The module mirrors "Crypto.Classes" except that errors are thrown as
-- exceptions instead of having returning types of @Either error result@
-- or @Maybe result@.
--
-- NB This module is experimental and might go away or be re-arranged.
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Classes.Exceptions 
    ( C.Hash(..)
    , C.hashFunc', C.hashFunc
    , C.BlockCipher, C.blockSize, C.encryptBlock, C.decryptBlock
    , C.keyLength
    , C.getIVIO, C.blockSizeBytes, C.keyLengthBytes, C.buildKeyIO
    , C.AsymCipher, C.publicKeyLength, C.privateKeyLength, C.buildKeyPairIO
    , C.Signing, C.signingKeyLength, C.verifyingKeyLength, C.verify
    , C.incIV, C.zeroIV, R.CryptoRandomGen, R.genSeedLength, R.reseedInfo, R.reseedPeriod, R.newGenIO
    --  Types
    , R.GenError(..), R.ReseedInfo(..), CipherError(..)
    -- Modes
    , C.ecb, C.unEcb, C.cbc, C.unCbc, C.ctr, C.unCtr, C.ctrLazy, C.unCtrLazy
    , C.cfb, C.unCfb, C.ofb, C.unOfb, C.cbcLazy, C.unCbcLazy, C.sivLazy, C.unSivLazy
    , C.siv, C.unSiv, C.ecbLazy, C.unEcbLazy, C.cfbLazy, C.unCfbLazy, C.ofbLazy
    , C.unOfbLazy
    -- Wrapped functions
    , buildKey, getIV, buildKeyGen
    , buildKeyPair, encryptAsym, decryptAsym
    , newGen, genBytes, genBytesWithEntropy, reseed, splitGen
    ) where

import qualified Crypto.Random     as R
import           Crypto.Random     (CryptoRandomGen)
import           Crypto.Types
import qualified Crypto.Classes    as C
import qualified Control.Exception as X
import qualified Data.ByteString   as B
import           Data.Data
import           Data.Typeable

data CipherError = GenError R.GenError
                 | KeyGenFailure
        deriving (Show, Read, Eq, Ord, Data, Typeable)

instance X.Exception CipherError

mExcept :: (X.Exception e) => e -> Maybe a -> a
mExcept e = maybe (X.throw e) id

eExcept :: (X.Exception e) => Either e a -> a
eExcept = either X.throw id

-- |Key construction from raw material (typically including key expansion)
--
-- This is a wrapper that can throw a 'CipherError' on exception.
buildKey :: C.BlockCipher k => B.ByteString -> k
buildKey = mExcept KeyGenFailure . C.buildKey

-- |Random 'IV' generation
--
-- This is a wrapper that can throw a 'GenError' on exception.
getIV :: (C.BlockCipher k, CryptoRandomGen g) => g -> (IV k, g)
getIV = eExcept . C.getIV

-- |Symmetric key generation
--
-- This is a wrapper that can throw a 'GenError' on exception.
buildKeyGen :: (CryptoRandomGen g, C.BlockCipher k) => g -> (k, g)
buildKeyGen = eExcept . C.buildKeyGen

-- |Asymetric key generation
--
-- This is a wrapper that can throw a 'GenError' on exception.
buildKeyPair :: (CryptoRandomGen g, C.AsymCipher p v) => g -> BitLength -> ((p,v), g)
buildKeyPair g = eExcept . C.buildKeyPair g

-- |Asymmetric encryption
--
-- This is a wrapper that can throw a 'GenError' on exception.
encryptAsym :: (CryptoRandomGen g, C.AsymCipher p v) => g -> p -> B.ByteString -> (B.ByteString, g)
encryptAsym g p = eExcept . C.encryptAsym g p

-- |Asymmetric decryption
--
-- This is a wrapper that can throw a GenError on exception.
decryptAsym :: (CryptoRandomGen g, C.AsymCipher p v) => g -> v -> B.ByteString -> (B.ByteString, g)
decryptAsym g v = eExcept . C.decryptAsym g v

-- |Instantiate a new random bit generator.  The provided
-- bytestring should be of length >= genSeedLength.  If the
-- bytestring is shorter then the call may fail (suggested
-- error: `NotEnoughEntropy`).  If the bytestring is of
-- sufficent length the call should always succeed.
--
-- This is a wrapper that can throw 'GenError' types as exceptions.
newGen :: CryptoRandomGen g => B.ByteString -> g
newGen = eExcept . R.newGen

-- | @genBytes len g@ generates a random ByteString of length
-- @len@ and new generator.  The 'MonadCryptoRandom' package
-- has routines useful for converting the ByteString to
-- commonly needed values (but 'cereal' or other
-- deserialization libraries would also work).
--
-- This is a wrapper that can throw 'GenError' types as exceptions.
genBytes :: CryptoRandomGen g => ByteLength -> g -> (B.ByteString, g)
genBytes l = eExcept . R.genBytes l

-- |@genBytesWithEntropy g i entropy@ generates @i@ random bytes and use
-- the additional input @entropy@ in the generation of the requested data
-- to increase the confidence our generated data is a secure random stream.
--
-- This is a wrapper that can throw 'GenError' types as exceptions.
genBytesWithEntropy :: CryptoRandomGen g => ByteLength -> B.ByteString -> g -> (B.ByteString, g)
genBytesWithEntropy l b = eExcept . R.genBytesWithEntropy l b

-- |If the generator has produced too many random bytes on its existing
-- seed it will throw a `NeedReseed` exception.  In that case, reseed the
-- generator using this function and a new high-entropy seed of length >=
-- `genSeedLength`.  Using bytestrings that are too short can result in an
-- exception (`NotEnoughEntropy`).
reseed :: CryptoRandomGen g => B.ByteString -> g -> g
reseed l = eExcept . R.reseed l

-- | While the safety and wisdom of a splitting function depends on the
-- properties of the generator being split, several arguments from
-- informed people indicate such a function is safe for NIST SP 800-90
-- generators.  (see libraries\@haskell.org discussion around Sept, Oct
-- 2010).  You can find implementations of such generators in the 'DRBG'
-- package.
--
-- This is a wrapper for 'Crypto.Random.splitGen' which throws errors as
-- exceptions.
splitGen :: CryptoRandomGen g => g -> (g,g)
splitGen = eExcept . R.splitGen
