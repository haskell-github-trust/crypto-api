{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 
 Authors: Thomas DuBuisson

This is the heart of the crypto-api package.  By making (or having) an instance
of Hash, AsymCipher, BlockCipher or StreamCipher you provide (or obtain) access
to any infrastructure built on these primitives include block cipher modes of
operation, hashing, hmac, signing, etc.  These classes allow users to build
routines that are agnostic to the algorithm used so changing algorithms is as
simple as changing a type signature.
-}
module Crypto.Classes where

  import Data.ByteString as B
  import Data.ByteString.Lazy as L
  import Crypto.Types
  import Data.Serialize
  import Data.Tagged

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
