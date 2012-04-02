{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable
-}

module Crypto.HMAC
	( hmac
	, hmac'
	, MacKey(..)
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Crypto.Classes
import Data.Serialize (encode)
import Data.Bits (xor)

-- | A key carrying phantom types @c@ and @d@, forcing the key data to only be used
-- by particular hash algorithms.
newtype MacKey c d = MacKey B.ByteString deriving (Eq, Ord, Show)

-- |Message authentication code calculation for lazy bytestrings.
-- @hmac k msg@ will compute an authentication code for @msg@ using key @k@
hmac :: (Hash c d) => MacKey c d -> L.ByteString -> d
hmac (MacKey k) msg = res
  where
  res = hash' . B.append ko . encode  . f . L.append ki $ msg
  f = hashFunc res
  keylen = B.length k
  blen = blockLength .::. res `div` 8
  k' = case compare keylen blen of
         GT -> B.append (encode . f . fc $ k) (B.replicate (blen - (outputLength .::. res `div` 8) ) 0x00)
         EQ -> k
         LT -> B.append k (B.replicate (blen - keylen) 0x00)
  ko = B.map (`xor` 0x5c) k'
  ki = fc $ B.map (`xor` 0x36) k'
  fc = L.fromChunks . \s -> [s]

-- | @hmac k msg@ will compute an authentication code for @msg@ using key @k@
hmac' :: (Hash c d) => MacKey c d -> B.ByteString -> d
hmac' k = hmac k . L.fromChunks . return
