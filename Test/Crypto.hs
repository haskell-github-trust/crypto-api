{-# LANGUAGE OverloadedStrings, ExistentialQuantification #-}
{-| Basic tests for some common cryptographic algorithms
 -
 - Most user only need to run the make/run tests functions:
 -
 -     runTests (makeMD5Tests (undefined :: MD5Digest))
 -}
module Test.Crypto
	( makeMD5Tests
	, makeSHA1Tests
	, makeSHA256Tests
	, makeSHA384Tests
	, makeSHA512Tests
	, runTests
	, Test(..)
	, KAT(..)
	, runKATs
	) where

import Test.QuickCheck
import Data.Crypto.Classes
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Control.Monad (forM)
import Data.Word (Word8)
import qualified Data.Binary as Bin
import qualified Data.Serialize as Ser
import Numeric (readHex)

instance Arbitrary Word8 where
    arbitrary = (arbitrary :: Gen Int) >>= return . fromIntegral

instance Arbitrary B.ByteString where
    arbitrary = do
        len <- choose (0,4096) :: Gen Int
        words <- forM [0..len] (\_ -> arbitrary)
        return $ B.pack words

instance Arbitrary L.ByteString where
    arbitrary = do
        len <- choose (0,10) :: Gen Int
        chunks <- vector len
        return $ L.fromChunks chunks

-- |Verify hashing a lazy bytestring is the same as
-- hashing the strict bytestring equivalent.
prop_LazyStrictEqual :: Hash c d => d -> L.ByteString -> Bool
prop_LazyStrictEqual d lps =
    let strict   = B.concat $ L.toChunks lps
	f  = hashFunc d
	f' = hashFunc' d
    in f lps == f' strict

-- |Verify the Serialize and Binary instances result
-- in bytestrings of the correct length for a given digest
prop_DigestLen :: Hash c d => d -> L.ByteString -> Bool
prop_DigestLen d lps =
	fromIntegral o == L.length h && o == B.length h'
  where f = hashFunc d
	f' = hashFunc' d
	h = Bin.encode . f $ lps
	h' = Ser.encode . f' . B.concat . L.toChunks $ lps
	o = outputLength `for` d

-- |Verify the Serilize and Binary (decode . encode = id)
prop_GetPut :: Hash c d => d -> L.ByteString -> Bool
prop_GetPut d lps =
    Bin.decode (Bin.encode h) == h && Ser.decode (Ser.encode h') == Right h'
  where
  f = hashFunc d
  f' = hashFunc' d
  h = f lps
  h' = f' . B.concat . L.toChunks $ lps

prop_BlockLengthIsByteAligned :: Hash c d => d -> Bool
prop_BlockLengthIsByteAligned d =
	let b = blockLength `for` d
	in b == (b `div` 8) * 8

prop_OutputLengthIsByteAligned :: Hash c d => d -> Bool
prop_OutputLengthIsByteAligned d =
	let b = outputLength `for` d
	in b == (b `div` 8) * 8

data Test = forall a. Testable a => T a String

makePropTests :: Hash c d => d -> [Test]
makePropTests d =
	[ T (prop_LazyStrictEqual d) "prop_LazyStrictEqual"
	, T (prop_DigestLen d) "prop_DigestLen"
	, T (prop_GetPut d) "prop_GetPut"
	, T (prop_BlockLengthIsByteAligned d) "prop_BlockLengthIsByteAligned"
	, T (prop_OutputLengthIsByteAligned d) "prop_OuputLengthIsByteAligned"
	]

makeBlockCipherTests = []

data KAT d = K L.ByteString d

runKATs :: Hash c d => [KAT d] -> Bool
runKATs = all goodKAT
  where
  goodKAT (K lps d) = hash lps == d

-- Known Answer Tests
aesKATs    = []

md5KATs :: Hash c d => d -> [KAT d]
md5KATs d =
	[ K "" (toD d "d41d8cd98f00b204e9800998ecf8427e")
	, K "a" (toD d "0cc175b9c0f1b6a831c399e269772661")
        , K "abc" (toD d "900150983cd24fb0d6963f7d28e17f72")
	, K "message digest" (toD d "f96b697d7cb7938d525a2f31aaf161d0")
	, K "abcdefghijklmnopqrstuvwxyz" (toD d "c3fcd3d76192e4007dfb496cca67e13b")
	, K "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" (toD d "d174ab98d277d9f5a5611c2c9f419d9f")
	, K "12345678901234567890123456789012345678901234567890123456789012345678901234567890" (toD d "57edf4a22be3c955ac49da2e2107b67a")
	]

toD d str = (Bin.decode  (toD' str)) `asTypeOf` d
  where
  toD' [] = L.empty
  toD' (_:[]) = error "Not an even number of hex characters in alledged 'digest'"
  toD' (a:b:xs) = L.cons (rHex (a:b:[])) (toD' xs)
  rHex = fst . head . readHex

dogStr = "The quick brown fox jumps over the lazy dog"
cogStr = "The quick brown fox jumps over the lazy cog"

sha1KATs d =
	[ K "" (toD d "da39a3ee5e6b4b0d3255bfef95601890afd80709")
	, K dogStr (toD d "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
	, K cogStr (toD d "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
	]
sha224KATs d =
	[ K "" (toD d "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
	, K dogStr (toD d "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525")
	, K cogStr (toD d "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b")
	]
sha256KATs d =
	[ K "" (toD d "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	, K dogStr
	  (toD d "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
	, K cogStr
	  (toD d "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be")
	]
sha384KATs d =
	[ K ""
	  (toD d "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
	, K dogStr
	  (toD d "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1")
	, K cogStr
	  (toD d "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b")
	]
sha512KATs d =
	[ K "" (toD d $ "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a92"
	            ++ "1d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417"
		    ++ "a81a538327af927da3e")
	, K dogStr (toD d $ "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a30"
	            ++ "9d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097"
	            ++ "821233fa0538f3db854fee6")
	, K cogStr (toD d $ "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1"
		    ++ "a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4"
		    ++ "cc8dfcab7da11c8ae5045")
	]

makeXTests :: Hash c d => String -> (d -> [KAT d]) -> d -> [Test]
makeXTests s k d = T (runKATs $ k d) (s ++ "-KAT") : makePropTests d

makeMD5Tests :: Hash c d => d -> [Test]
makeMD5Tests = makeXTests "md5" md5KATs 

makeSHA1Tests :: Hash c d => d -> [Test]
makeSHA1Tests = makeXTests "sha1" sha1KATs

makeSHA224Tests :: Hash c d => d -> [Test]
makeSHA224Tests = makeXTests "sha224" sha224KATs

makeSHA256Tests :: Hash c d => d -> [Test]
makeSHA256Tests = makeXTests "sha256" sha256KATs

makeSHA384Tests :: Hash c d => d -> [Test]
makeSHA384Tests = makeXTests "sha384" sha384KATs

makeSHA512Tests :: Hash c d => d -> [Test]
makeSHA512Tests = makeXTests "sha512" sha512KATs

-- |Run a single test
runTest :: Test -> IO ()
runTest (T a s) = do
    putStr ("prop_" ++ s ++ ": ")
    quickCheck a

-- |Run a list of tests
runTests :: [Test] -> IO ()
runTests = mapM_ runTest
