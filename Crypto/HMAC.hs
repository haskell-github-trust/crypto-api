module Crypto.HMAC
	( hmac
	, hmac'
	, MacKey(..)
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Crypto.Classes
import Data.Serialize (encode)
import qualified Data.Binary as Bin
import Data.Bits (xor)

newtype MacKey = MacKey B.ByteString deriving (Eq, Ord, Show)

-- |Message authentication code calculation for lazy bytestrings.
-- @hmac k msg@ will compute an authentication code for @msg@ using key @k@
hmac :: (Hash c d) => MacKey -> L.ByteString -> d
hmac (MacKey k) msg = res
  where
  res = f . L.append ko . Bin.encode  . f . L.append ki $ msg
  f = hash
  keylen = B.length k
  blen = blockLength .::. res `div` 8
  k' = case compare keylen blen of
         GT -> encode . f . fc $ k
         EQ -> k
         LT -> B.append k (B.replicate (blen - keylen) 0x00)
  ko = fc $ B.map (`xor` 0x5c) k'
  ki = fc $ B.map (`xor` 0x36) k'
  fc = L.fromChunks . \s -> [s]

-- | @hmac k msg@ will compute an authentication code for @msg@ using key @k@
hmac' :: (Hash c d) => MacKey -> B.ByteString -> d
hmac' k = hmac k . L.fromChunks . return
