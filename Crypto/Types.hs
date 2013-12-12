{-# LANGUAGE DeriveDataTypeable #-}
-- |Type aliases used throughout the crypto-api modules.
module Crypto.Types where

import qualified Control.Exception      as X
import           Data.Data
import           Data.Typeable
import           Data.ByteString        as B
import           Data.ByteString.Lazy   as L

-- |Initilization Vectors for BlockCipher implementations (IV k) are
-- used for various modes and guarrenteed to be blockSize bits long.
-- The common ways to obtain an IV are to generate one ('getIV' or
-- 'getIVIO') or to use one provided with the ciphertext (using the
-- 'Serialize' instance of IV).
--
-- 'zeroIV' also exists and is of particular use for starting 'ctr'
-- mode with a fresh key.
data IV k = IV { initializationVector :: {-# UNPACK #-} !B.ByteString
               } deriving (Eq, Ord, Show)


-- |The length of a field (usually a ByteString) in bits
type BitLength = Int

-- |The length fo a field in bytes.
type ByteLength = Int

data BlockCipherError = InputTooLong String
                      | AuthenticationFailed String
                      | Other String
  deriving (Eq, Ord, Show, Read, Data, Typeable)

instance X.Exception BlockCipherError

