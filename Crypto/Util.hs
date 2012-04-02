-- |A small selection of utilities that might be of use to others working with bytestring/number combinations.
module Crypto.Util where
import qualified Data.ByteString as B
import Data.ByteString.Unsafe (unsafeIndex)
import Data.Bits (shiftL, shiftR)

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

-- |@bs2i bs@ converts the 'ByteString' @bs@ to an 'Integer' (inverse of 'i2bs')
bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

