{-# LANGUAGE FlexibleInstances, TypeSynonymInstances, DeriveDataTypeable, CPP,
             BangPatterns #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 


 This module is for instantiating cryptographicly strong
determinitic random bit generators (DRBGs, aka PRNGs) For the simple
use case of using the system random number generator
('System.Entropy') to seed the DRBG:

@   g <- newGenIO
@

 Users needing to provide their own entropy can call 'newGen' directly
 
@    entropy <- getEntropy nrBytes
    let generator = newGen entropy
@

-}

module Crypto.Random
       ( -- * Basic Interface
         CryptoRandomGen(..)
       , GenError (..)
       , ReseedInfo (..)
         -- * Helper functions and expanded interface
       , splitGen
       , throwLeft
         -- * Instances
       , SystemRandom
       ) where

import Control.Monad (liftM)
import Control.Exception
import Crypto.Types
import Crypto.Util
import Data.Bits (xor, setBit, shiftR, shiftL, (.&.))
import Data.Data
import Data.List (foldl')
import Data.Tagged
import Data.Typeable
import Data.Word
import System.Entropy
import System.IO.Unsafe(unsafeInterleaveIO)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Foreign.ForeignPtr as FP

#if MIN_VERSION_tagged(0,2,0)
import Data.Proxy
#endif

-- |Generator failures should always return the appropriate GenError.
-- Note 'GenError' in an instance of exception but wether or not an
-- exception is thrown depends on if the selected generator (read:
-- if you don't want execptions from code that uses 'throw' then
-- pass in a generator that never has an error for the used functions)
data GenError =
          GenErrorOther String  -- ^ Misc
        | RequestedTooManyBytes -- ^ Requested more bytes than a
                                -- single pass can generate (The
                                -- maximum request is generator
                                -- dependent)
        | RangeInvalid          -- ^ When using @genInteger g (l,h)@
                                -- and @logBase 2 (h - l) > (maxBound
                                -- :: Int)@.
        | NeedReseed            -- ^ Some generators cease operation
                                -- after too high a count without a
                                -- reseed (ex: NIST SP 800-90)
        | NotEnoughEntropy      -- ^ For instantiating new generators
                                -- (or reseeding)
        | NeedsInfiniteSeed     -- ^ This generator can not be
                                -- instantiated or reseeded with a
                                -- finite seed (ex: 'SystemRandom')
  deriving (Eq, Ord, Show, Read, Data, Typeable)

data ReseedInfo
    = InXBytes {-# UNPACK #-} !Word64   -- ^ Generator needs reseeded in X bytes
    | InXCalls {-# UNPACK #-} !Word64   -- ^ Generator needs reseeded in X calls
    | NotSoon                           -- ^ The bound is over 2^64 bytes or calls
    | Never                             -- ^ This generator never reseeds (ex: 'SystemRandom')
  deriving (Eq, Ord, Show, Read, Data, Typeable)

instance Exception GenError

-- |A class of random bit generators that allows for the possibility
-- of failure, reseeding, providing entropy at the same time as
-- requesting bytes
--
-- Minimum complete definition: `newGen`, `genSeedLength`, `genBytes`,
-- `reseed`, `reseedInfo`, `reseedPeriod`.
class CryptoRandomGen g where
        -- |Instantiate a new random bit generator.  The provided
        -- bytestring should be of length >= genSeedLength.  If the
        -- bytestring is shorter then the call may fail (suggested
        -- error: `NotEnoughEntropy`).  If the bytestring is of
        -- sufficent length the call should always succeed.
        newGen :: B.ByteString -> Either GenError g

        -- |Length of input entropy necessary to instantiate or reseed
        -- a generator
        genSeedLength :: Tagged g ByteLength

        -- | @genBytes len g@ generates a random ByteString of length
        -- @len@ and new generator.  The "MonadCryptoRandom" package
        -- has routines useful for converting the ByteString to
        -- commonly needed values (but "cereal" or other
        -- deserialization libraries would also work).
        --
        -- This routine can fail if the generator has gone too long
        -- without a reseed (usually this is in the ball-park of 2^48
        -- requests).  Suggested error in this cases is `NeedReseed`
        genBytes        :: ByteLength -> g -> Either GenError (B.ByteString, g)

        -- | Indicates how soon a reseed is needed
        reseedInfo :: g -> ReseedInfo

        -- | Indicates the period between reseeds (constant for most generators).
        reseedPeriod :: g -> ReseedInfo

        -- |@genBytesWithEntropy g i entropy@ generates @i@ random
        -- bytes and use the additional input @entropy@ in the
        -- generation of the requested data to increase the confidence
        -- our generated data is a secure random stream.
        --
        -- Some generators use @entropy@ to perturb the state of the
        -- generator, meaning:
        --
        -- @
        --     (_,g2') <- genBytesWithEntropy len g1 ent
        --     (_,g2 ) <- genBytes len g1
        --     g2 /= g2'
        -- @
        --
        -- But this is not required.
        --
        -- Default:
        -- 
        -- @
        --     genBytesWithEntropy g bytes entropy = xor entropy (genBytes g bytes)
        -- @
        genBytesWithEntropy     :: ByteLength -> B.ByteString -> g -> Either GenError (B.ByteString, g)
        genBytesWithEntropy len entropy g =
                let res = genBytes len g
                in case res of
                        Left err -> Left err
                        Right (bs,g') ->
                                let entropy' = B.append entropy (B.replicate (len - B.length entropy) 0)
                                in Right (zwp' entropy' bs, g')

        -- |If the generator has produced too many random bytes on its
        -- existing seed it will return `NeedReseed`.  In that case,
        -- reseed the generator using this function and a new
        -- high-entropy seed of length >= `genSeedLength`.  Using
        -- bytestrings that are too short can result in an error
        -- (`NotEnoughEntropy`).
        reseed          :: B.ByteString -> g -> Either GenError g

        -- |By default this uses "System.Entropy" to obtain
        -- entropy for `newGen`.
        -- WARNING: The default implementation opens a file handle which will never be closed!
        newGenIO :: IO g
        newGenIO = go 0
          where
          go 1000 = throw $ GenErrorOther $ 
                          "The generator instance requested by" ++
                          "newGenIO never instantiates (1000 tries). " ++
                          "It must be broken."
          go i = do
                let p = Proxy
                    getTypedGen :: (CryptoRandomGen g) => Proxy g -> IO (Either GenError g)
                    getTypedGen pr = liftM newGen (getEntropy $ proxy genSeedLength pr)
                res <- getTypedGen p
                case res of
                        Left _ -> go (i+1)
                        Right g -> return (g `asProxyTypeOf` p)

-- | Get a random number generator based on the standard system entropy source
--   WARNING: This function opens a file handle which will never be closed!
getSystemGen :: IO SystemRandom
getSystemGen = do
        ch <- openHandle
        let getBS = unsafeInterleaveIO $ do
                bs <- hGetEntropy ch ((2^15) - 16)
                more <- getBS
                return (bs:more)
        liftM (SysRandom . L.fromChunks) getBS

-- |Not that it is technically correct as an instance of
-- 'CryptoRandomGen', but simply because it's a reasonable engineering
-- choice here is a CryptoRandomGen which streams the system
-- randoms. Take note:
-- 
--  * It uses the default definition of 'genByteWithEntropy'
--
--  * 'newGen' will always fail!
--
--  * 'reseed' will always fail!
--
--  * the handle to the system random is never closed
--
data SystemRandom = SysRandom L.ByteString

instance CryptoRandomGen SystemRandom where
  newGen _ = Left NeedsInfiniteSeed
  genSeedLength = Tagged maxBound
  genBytes req (SysRandom bs) =
    let reqI = fromIntegral req
        rnd  = L.take reqI bs
        rest = L.drop reqI bs
    in if L.length rnd == reqI
        then Right (B.concat $ L.toChunks rnd, SysRandom rest)
        else Left RequestedTooManyBytes
  reseed _ _ = Left NeedsInfiniteSeed
  newGenIO = getSystemGen
  reseedInfo _ = Never
  reseedPeriod _ = Never

-- | While the safety and wisdom of a splitting function depends on the
-- properties of the generator being split, several arguments from
-- informed people indicate such a function is safe for NIST SP 800-90
-- generators.  (see libraries\@haskell.org discussion around Sept, Oct
-- 2010).  You can find implementations of such generators in the 'DRBG'
-- package.
splitGen :: CryptoRandomGen g => g -> Either GenError (g,g)
splitGen g =
  let e = genBytes' (genSeedLength `for` g) g
  in case e of
    Left e -> Left e
    Right (ent,g') -> 
       case newGen ent of
                Right new -> Right (g',new)
                Left e -> Left e
  where
  genBytes' seedLength g
    | seedLength < 0      = Left NeedsInfiniteSeed
    | seedLength > (2^30) = Left NeedsInfiniteSeed
    | otherwise           = genBytes seedLength g
