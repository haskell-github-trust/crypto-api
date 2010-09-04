{-# LANGUAGE CPP #-}
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

#if defined(_WIN32)
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
newtype CryptHandle = CH CInt
foreign import stdcall unsafe "CryptAcquireContext"
	c_cryptAcquireCtx :: ... -> IO CInt
foreign import stdcall unsafe "CryptGenRandom"
	c_cryptGenRandom :: CInt -> CInt -> Ptr Word8 -> IO ()
foreign import stdcall unsafe "CryptReleaseContext"
	c_cryptReleaseCtx :: CInt -> CInt -> IO ()

cryptAcquireCtx ... = liftM CH (c_cryptAcquireCtx ...)

-- FIXME check errors
cryptGenRandom :: CryptHandle -> Int -> IO B.ByteString
cryptGenRandom (CH h) i = B.create i (c_cryptGenRandom h (fromIntegral i))

-- FIXME check errors
cryptReleaseCtx :: CryptHandle -> IO ()
cryptReleaseCtx (CH h) = c_cryptReleaseCtx h 0

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

openHandle :: IO CryptHandle
openHandle = liftM CH cryptAcquireCtx

closeHandle (CH h) = cryptReleaseCtx h

hGetEntropy :: CryptHandle -> Int -> IO B.ByteString 
hGetEntropy (CH h) = cryptGenRandom h

#else
newtype CryptHandle = CH Handle


openHandle :: IO CryptHandle
openHandle = liftM CH (openFile "/dev/urandom" ReadMode)

closeHandle :: CryptHandle -> IO ()
closeHandle (CH h) = hClose h

hGetEntropy :: CryptHandle -> Int -> IO B.ByteString 
hGetEntropy (CH h) = B.hGet h

-- |Inefficiently get a specific number of bytes of cryptographically
-- secure random data using the system-specific facilities.
--
-- This function will return zero bytes
-- on platforms without a secure RNG!
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

