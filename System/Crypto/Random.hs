{-# LANGUAGE CPP, ForeignFunctionInterface, BangPatterns #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable

 Obtain entropy from system sources.  This module is rather untested on Windows (or testers never provided feedback),
 though testing was requested from the community - please e-mail the maintainer with test results.
-}

module System.Crypto.Random 
	( getEntropy
	, CryptHandle
	, openHandle
	, hGetEntropy
	, closeHandle
	) where

import System.IO (openFile, hClose, IOMode(..), Handle)
import Control.Monad (liftM)
import Data.ByteString as B
import Data.ByteString.Lazy as L
import Crypto.Types

#if defined(isWindows)
{- C example for windows rng - taken from a blog, can't recall which one but thank you!
        #include <Windows.h>
        #include <Wincrypt.h>
        ...
        //
        // DISCLAIMER: Don't forget to check your error codes!!
        // I am not checking as to make the example simple...
        //
        HCRYPTPROV hCryptCtx = NULL;
        BYTE randomArray[128];

        CryptAcquireContext(&hCryptCtx, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptGenRandom(hCryptCtx, 128, randomArray);
        CryptReleaseContext(hCryptCtx, 0);
-}

import Data.ByteString.Internal as B
import Data.Int (Int32)
import Data.Word (Word32, Word8)
import Foreign.C.String (CString, withCString)
import Foreign.Ptr (Ptr, nullPtr)
import Foreign.Marshal.Alloc (alloca)
import Foreign.Marshal.Utils (toBool)
import Foreign.Storable (peek)

newtype CryptHandle = CH Word32

-- Define the constants we need from WinCrypt.h 
msDefProv :: String
msDefProv = "Microsoft Base Cryptographic Provider v1.0"
provRSAFull :: Word32
provRSAFull = fromIntegral 1
cryptVerifyContext :: Word32
cryptVerifyContext = fromIntegral 0xF0000000

-- Declare the required CryptoAPI imports 
foreign import stdcall unsafe "CryptAcquireContextA"
   c_cryptAcquireCtx :: Ptr Word32 -> CString -> CString -> Word32 -> Word32 -> IO Int32
foreign import stdcall unsafe "CryptGenRandom"
   c_cryptGenRandom :: Word32 -> Word32 -> Ptr Word8 -> IO Int32
foreign import stdcall unsafe "CryptReleaseContext"
   c_cryptReleaseCtx :: Word32 -> Word32 -> IO Int32

cryptAcquireCtx :: IO Word32
cryptAcquireCtx = 
   alloca $ \handlePtr -> 
      withCString msDefProv $ \provName -> do
         stat <- c_cryptAcquireCtx handlePtr nullPtr provName (fromIntegral 1) (fromIntegral cryptVerifyContext)
         if (toBool stat)
            then peek handlePtr
            else fail "c_cryptAcquireCtx"

cryptGenRandom :: Word32 -> Int -> IO B.ByteString
cryptGenRandom h i = 
   B.create i $ \c_buffer -> do
      stat <- c_cryptGenRandom (fromIntegral h) (fromIntegral i) c_buffer
      if (toBool stat)
         then return ()
         else fail "c_cryptGenRandom"

cryptReleaseCtx :: Word32 -> IO ()
cryptReleaseCtx h = do
   stat <- c_cryptReleaseCtx h 0
   if (toBool stat)
      then return ()
      else fail "c_cryptReleaseCtx"

-- |Inefficiently get a specific number of bytes of cryptographically
-- secure random data using the system-specific facilities.
--
-- This function will return zero bytes
-- on platforms without a secure RNG!
getEntropy :: ByteLength -> IO B.ByteString
getEntropy n = do
	h <- cryptAcquireCtx
	bs <- cryptGenRandom h n
	let !bs' = bs
	cryptReleaseCtx h
	return bs'

-- |Open a handle from which random data can be read
openHandle :: IO CryptHandle
openHandle = liftM CH cryptAcquireCtx

-- |Close the `CryptHandle`
closeHandle (CH h) = cryptReleaseCtx h

-- |Read from `CryptHandle`
hGetEntropy :: CryptHandle -> Int -> IO B.ByteString 
hGetEntropy (CH h) = cryptGenRandom h

#else
-- |Handle for manual resource mangement
newtype CryptHandle = CH Handle

-- |Open a `CryptHandle`
openHandle :: IO CryptHandle
openHandle = liftM CH (openFile "/dev/urandom" ReadMode)

-- |Close the `CryptHandle`
closeHandle :: CryptHandle -> IO ()
closeHandle (CH h) = hClose h

-- |Read random data from a `CryptHandle`
hGetEntropy :: CryptHandle -> Int -> IO B.ByteString 
hGetEntropy (CH h) = B.hGet h

-- |Inefficiently get a specific number of bytes of cryptographically
-- secure random data using the system-specific facilities.
--
-- Use '/dev/urandom' on *nix and CryptAPI when on Windows.
getEntropy :: ByteLength -> IO B.ByteString
getEntropy = getEnt "/dev/urandom"

-- "getTrueEntropy" was a thought, but if you are so security sensitive as to
-- know you want /dev/random then you should be concerned about
-- the platform you sit on, thus writing non-portable code
-- reading /dev/random yourself is a non-issue.
--
-- getTrueEntropy :: ByteLength -> IO B.ByteString
-- getTrueEntropy = getEnt "/dev/random"

getEnt :: FilePath -> ByteLength -> IO B.ByteString
getEnt file n = do
        h <- openFile file ReadMode
        bs <- B.hGet h n
        let !bs' = bs
        hClose h
        return bs'
#endif

