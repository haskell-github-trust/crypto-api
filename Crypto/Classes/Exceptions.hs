-- |The module mirrors 'Crypto.Classes' except that errors are thrown as
-- exceptions instead of having returning types of @Either error result@
-- or @Maybe result@.
--
-- NB This module is experimental and might go away or be re-arranged.
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Classes.Exceptions 
    ( C.Hash(..)
    , C.hashFunc, C.hashFunc'
    , C.BlockCipher, C.blockSize, C.encryptBlock, C.decryptBlock
    , C.keyLength
    , C.getIVIO, C.blockSizeBytes, C.keyLengthBytes, C.buildKeyIO
    , C.AsymCipher, C.publicKeyLength, C.privateKeyLength, C.buildKeyPairIO
    , C.Signing, C.signingKeyLength, C.verifyingKeyLength, C.verify
    , C.incIV, C.zeroIV
    -- Modes
    , C.ecb, C.unEcb, C.cbc, C.unCbc, C.ctr, C.unCtr, C.ctrLazy, C.unCtrLazy
    , C.cfb, C.unCfb, C.ofb, C.unOfb, C.cbcLazy, C.unCbcLazy, C.sivLazy, C.unSivLazy
    , C.siv, C.unSiv, C.ecbLazy, C.unEcbLazy, C.cfbLazy, C.unCfbLazy, C.ofbLazy
    , C.unOfbLazy
    -- Wrapped functions
    , buildKey, getIV, buildKeyGen
    , buildKeyPair, encryptAsym, decryptAsym
    ) where

import           Crypto.Random
import           Crypto.Types
import qualified Crypto.Classes    as C
import qualified Control.Exception as X
import qualified Data.ByteString   as B
import           Data.Data
import           Data.Typeable

data CipherError = GenError GenError
                 | KeyGenFailure
        deriving (Show, Read, Eq, Ord, Data, Typeable)

instance X.Exception CipherError

mExcept :: (X.Exception e) => e -> Maybe a -> a
mExcept e = maybe (X.throw e) id

eExcept :: (X.Exception e) => Either e a -> a
eExcept = either X.throw id

buildKey :: C.BlockCipher k => B.ByteString -> k
buildKey = mExcept KeyGenFailure . C.buildKey

getIV :: (C.BlockCipher k, CryptoRandomGen g) => g -> (IV k, g)
getIV = eExcept . C.getIV

buildKeyGen :: (CryptoRandomGen g, C.BlockCipher k) => g -> (k, g)
buildKeyGen = eExcept . C.buildKeyGen

buildKeyPair :: (CryptoRandomGen g, C.AsymCipher p v) => g -> BitLength -> ((p,v), g)
buildKeyPair g = eExcept . C.buildKeyPair g

encryptAsym :: (CryptoRandomGen g, C.AsymCipher p v) => g -> p -> B.ByteString -> (B.ByteString, g)
encryptAsym g p = eExcept . C.encryptAsym g p

decryptAsym :: (CryptoRandomGen g, C.AsymCipher p v) => g -> v -> B.ByteString -> (B.ByteString, g)
decryptAsym g v = eExcept . C.decryptAsym g v
