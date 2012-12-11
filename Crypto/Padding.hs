{-|
  Maintainer: Thomas.DuBuisson@gmail.com
  Stability: beta
  Portability: portable

PKCS5 (RFC 1423) and IPSec ESP (RFC 4303)
padding methods are implemented both as trivial functions operating on
bytestrings and as 'Put' routines usable from the "Data.Serialize"
module.  These methods do not work for algorithms or pad sizes in
excess of 255 bytes (2040 bits, so extremely large as far as cipher
needs are concerned).

-}

module Crypto.Padding
        (
        -- * PKCS5 (RFC 1423) based [un]padding routines
          padPKCS5
        , padBlockSize
        , putPaddedPKCS5
        , unpadPKCS5safe
        , unpadPKCS5
        -- * ESP (RFC 4303) [un]padding routines
        , padESP, unpadESP
        , padESPBlockSize
        , putPadESPBlockSize, putPadESP
        ) where

import Data.Serialize.Put
import Crypto.Classes
import Crypto.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

-- |PKCS5 (aka RFC1423) padding method.
-- This method will not work properly for pad modulos > 256
padPKCS5 :: ByteLength -> B.ByteString -> B.ByteString
padPKCS5 len bs = runPut $ putPaddedPKCS5 len bs

-- | Ex:
--
-- @
--     putPaddedPKCS5 m bs
-- @
--
-- Will pad out `bs` to a byte multiple
-- of `m` and put both the bytestring and it's padding via 'Put'
-- (this saves on copying if you are already using Cereal).
putPaddedPKCS5 :: ByteLength -> B.ByteString -> Put
putPaddedPKCS5 0 bs = putByteString bs >> putWord8 1
putPaddedPKCS5 len bs = putByteString bs >> putByteString pad
  where
  pad = B.replicate padLen padValue
  r   = len - (B.length bs `rem` len)
  padLen = if r == 0 then len else r
  padValue = fromIntegral padLen

-- |PKCS5 (aka RFC1423) padding method using the BlockCipher instance
-- to determine the pad size.
padBlockSize :: BlockCipher k => k -> B.ByteString -> B.ByteString
padBlockSize k = runPut . putPaddedBlockSize k

-- |Leverages 'putPaddedPKCS5' to put the bytestring and padding
-- of sufficient length for use by the specified block cipher.
putPaddedBlockSize :: BlockCipher k => k -> B.ByteString -> Put
putPaddedBlockSize k bs = putPaddedPKCS5 (blockSizeBytes `for` k) bs

-- | unpad a strict bytestring padded in the typical PKCS5 manner.
-- This routine verifies all pad bytes and pad length match correctly.
unpadPKCS5safe :: B.ByteString -> Maybe B.ByteString
unpadPKCS5safe bs
        | bsLen > 0 && B.all (== padLen) pad && B.length pad == pLen = Just msg
        | otherwise = Nothing
  where
  bsLen = B.length bs
  padLen = B.last bs
  pLen = fromIntegral padLen
  (msg,pad) = B.splitAt (bsLen - pLen) bs

-- |unpad a strict bytestring without checking the pad bytes and
-- length any more than necessary.
unpadPKCS5 :: B.ByteString -> B.ByteString
unpadPKCS5 bs = if bsLen == 0 then bs else msg
  where
  bsLen = B.length bs
  padLen = B.last bs
  pLen = fromIntegral padLen
  (msg,_) = B.splitAt (bsLen - pLen) bs

-- | Pad a bytestring to the IPSEC esp specification
--
-- > padESP m payload
--
-- is equivilent to:
-- 
-- @
--               (msg)       (padding)       (length field)
--     B.concat [payload, B.pack [1,2,3,4..], B.pack [padLen]]
-- @
--
-- Where:
--
-- * the msg is any payload, including TFC.
-- 
-- * the padding is <= 255
-- 
-- * the length field is one byte.
--
--  Notice the result bytesting length remainder `r` equals zero.  The lack
--  of a \"next header\" field means this function is not directly useable for
--  an IPSec implementation (copy/paste the 4 line function and add in a
--  \"next header\" field if you are making IPSec ESP).
padESP :: Int -> B.ByteString -> B.ByteString
padESP i bs = runPut (putPadESP i bs)

-- | Like padESP but use the BlockCipher instance to determine padding size
padESPBlockSize :: BlockCipher k => k -> B.ByteString -> B.ByteString
padESPBlockSize k bs = runPut (putPadESPBlockSize k bs)

-- | Like putPadESP but using the BlockCipher instance to determine padding size
putPadESPBlockSize :: BlockCipher k => k -> B.ByteString -> Put
putPadESPBlockSize k bs = putPadESP (blockSizeBytes `for` k) bs

-- | Pad a bytestring to the IPSEC ESP specification using 'Put'.
-- This can reduce copying if you are already using 'Put'.
putPadESP :: Int -> B.ByteString -> Put
putPadESP 0 bs = putByteString bs >> putWord8 0
putPadESP l bs = do
        putByteString bs
        putByteString pad
        putWord8 pLen
  where
  pad = B.take padLen espPad
  padLen = l - ((B.length bs + 1) `rem` l)
  pLen = fromIntegral padLen

-- |A static espPad allows reuse of a single B.pack'ed pad for all calls to padESP
espPad = B.pack [1..255]

-- | unpad and return the padded message ('Nothing' is returned if the padding is invalid)
unpadESP :: B.ByteString -> Maybe B.ByteString
unpadESP bs =
        if bsLen == 0 || not (constTimeEq (B.take pLen pad) (B.take pLen espPad))
                then Nothing
                else Just msg
  where
  bsLen  = B.length bs
  padLen = B.last bs
  pLen   = fromIntegral padLen
  (msg,pad) = B.splitAt (bsLen - (pLen + 1)) bs
