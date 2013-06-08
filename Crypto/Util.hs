-- |A small selection of utilities that might be of use to others working with bytestring/number combinations.
module Crypto.Util where

import qualified Data.ByteString as B
import Data.ByteString.Unsafe (unsafeIndex, unsafeUseAsCStringLen)
import Data.Bits (shiftL, shiftR)
import Data.Bits (xor, setBit, shiftR, shiftL)
import Control.Exception (Exception, throw)
import Data.Tagged
import System.IO.Unsafe
import Foreign.C.Types
import Foreign.Ptr

-- |@incBS bs@ inefficiently computes the value @i2bs (8 * B.length bs) (bs2i bs + 1)@
incBS :: B.ByteString -> B.ByteString
incBS bs = B.concat (go bs (B.length bs - 1))
  where
  go bs i
        | B.length bs == 0     = []
        | unsafeIndex bs i == 0xFF = (go (B.init bs) (i-1)) ++ [B.singleton 0]
        | otherwise            = [B.init bs] ++ [B.singleton $ (unsafeIndex bs i) + 1]
{-# INLINE incBS #-}


-- |@i2bs bitLen i@ converts @i@ to a 'ByteString' of @bitLen@ bits (must be a multiple of 8).
i2bs :: Int -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)
{-# INLINE i2bs #-}

-- |@i2bs_unsized i@ converts @i@ to a 'ByteString' of sufficient bytes to express the integer.
-- The integer must be non-negative and a zero will be encoded in one byte.
i2bs_unsized :: Integer -> B.ByteString
i2bs_unsized 0 = B.singleton 0
i2bs_unsized i = B.reverse $ B.unfoldr (\i' -> if i' <= 0 then Nothing else Just (fromIntegral i', (i' `shiftR` 8))) i
{-# INLINE i2bs_unsized #-}

-- | Useful utility to extract the result of a generator operation
-- and translate error results to exceptions.
throwLeft :: Exception e => Either e a -> a
throwLeft (Left e)  = throw e
throwLeft (Right a) = a

-- |Obtain a tagged value for a particular instantiated type.
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

-- |Helper function to convert bytestrings to integers
bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be
-- optimized (at compile time). to use the bytestring libraries
-- 'zipWith'' function.
zwp' :: B.ByteString -> B.ByteString -> B.ByteString
zwp' a = B.pack . B.zipWith xor a
{-# INLINE zwp' #-}

