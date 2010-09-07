{-# LANGUAGE OverloadedStrings, ExistentialQuantification, ViewPatterns #-}
{-|
 Maintainer: Thomas.DuBuisson@gmail.com
 Stability: beta
 Portability: portable 

  Basic tests for some common cryptographic algorithms
  
   Most user only need to run the {make,run}Tests functions:
  
>        runTests (makeMD5Tests (undefined :: MD5Digest))
  
   or
  
>        runTests =<< makeAESTests (undefined :: AESKey)
  
   TODO: More KATs are needed - particularly ones for non-AES, SHA, or MD5
   algorithms.
 -}
module Test.Crypto
	(
	-- * Test Infrastructure
	  runTests
	, Test(..)
	-- * Hash KATs
	, makeMD5Tests
	, makeSHA1Tests
	, makeSHA256Tests
	, makeSHA384Tests
	, makeSHA512Tests
	-- * Block Cipher KATs
	, makeAESTests
	-- * Hash property tests
	, prop_LazyStrictEqual
	, prop_DigestLen
	, prop_GetPutHash
	, prop_BlockLengthIsByteAligned
	, prop_OutputLengthIsByteAligned
	-- * Utils
	, hexStringToBS
	) where

import Test.QuickCheck
import Test.ParseNistKATs
import Crypto.Classes
import Crypto.Modes
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Control.Monad (forM, liftM, filterM)
import Data.Word (Word8)
import Data.Either (rights)
import Data.Maybe (maybeToList)
import Data.List (intersperse)
import qualified Data.Binary as Bin
import qualified Data.Serialize as Ser
import Numeric (readHex)
import Data.Maybe (fromJust)
import Text.Parsec
import Text.Parsec.ByteString
import System.Directory (getDirectoryContents, doesFileExist)
import System.FilePath (takeFileName, combine, dropExtension, (</>))
import Paths_crypto_api

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
	o = (outputLength `for` d) `div` 8

-- |Verify the Serilize and Binary (decode . encode = id)
prop_GetPutHash :: Hash c d => d -> L.ByteString -> Bool
prop_GetPutHash d lps =
    Bin.decode (Bin.encode h) == h && Ser.decode (Ser.encode h') == Right h'
  where
  f = hashFunc d
  f' = hashFunc' d
  h = f lps
  h' = f' . B.concat . L.toChunks $ lps

-- |verify:
--
-- > blockLength .::. d `rem` 8 == 0
prop_BlockLengthIsByteAligned :: Hash c d => d -> Bool
prop_BlockLengthIsByteAligned d = blockLength .::. d `rem` 8 == 0

-- |verify
--
-- > outputLength .::. d `rem` 8 == 0
prop_OutputLengthIsByteAligned :: Hash c d => d -> Bool
prop_OutputLengthIsByteAligned d = blockLength .::. d `rem` 8 == 0

-- |A Test can either be a quickcheck property (constructor 'T') or a
-- known answer test (aka KAT, constructor 'TK').  Known answer tests
-- are simply stored as their boolean result along with a test name.
data Test = forall a. Testable a => T a String | TK Bool String

instance Show Test where
	show (T _ name)  = "Test    " ++ name
	show (TK b name) = "KA Test " ++ name

katToTest :: (Eq b) => KAT a b -> Test
katToTest (K i f o s) = TK (f i == o) s

makeHashPropTests :: Hash c d => d -> [Test]
makeHashPropTests d =
	[ T (prop_LazyStrictEqual d) "LazyStrictEqual"
	, T (prop_DigestLen d) "DigestLen"
	, T (prop_GetPutHash d) "GetPutHash"
	, T (prop_BlockLengthIsByteAligned d) "BlockLengthIsByteAligned"
	, T (prop_OutputLengthIsByteAligned d) "OuputLengthIsByteAligned"
	]

-- |FIXME make some generic blockcipher tests
makeBlockCipherPropTests :: BlockCipher k => k -> [Test]
makeBlockCipherPropTests _ = []

data KAT i o = K i (i -> o) o String

runKATs :: (Eq o) => [KAT i o] -> Bool
runKATs = all goodKAT
  where
  goodKAT (K i f o _) = f i == o

-- *Known Answer Tests
toD :: Hash c d => d -> String -> d
toD d str = (Bin.decode $ L.fromChunks [hexStringToBS str]) `asTypeOf` d

-- |Convert hex strings to bytestrings, for example:
-- 
-- > "3adf91c0" ==> B.pack [0x3a, 0xdf, 0x91, 0xc0]
--
-- Strings of odd length will cause an exception as will non-hex characters such as '0x'.
hexStringToBS :: String -> B.ByteString
hexStringToBS [] = B.empty
hexStringToBS (_:[]) = error "Not an even number of hex characters in alledged 'digest'"
hexStringToBS (a:b:xs) = B.cons (rHex (a:b:[])) (hexStringToBS xs)
  where
  rHex = fst . head . readHex

dogStr = "The quick brown fox jumps over the lazy dog"
cogStr = "The quick brown fox jumps over the lazy cog"

getAES_KATs :: BlockCipher k => k -> IO [KAT B.ByteString B.ByteString]
getAES_KATs k = do
	dataDir <- getDataFileName ("Test" </> "KAT_AES")
	filesAndDirs <- getDirectoryContents dataDir
	files <- filterM doesFileExist (map (combine dataDir) filesAndDirs)
	recEs <- mapM (parseFromFile parseCategory) files
	let recs = map snd (rights recEs)
	    fName = map takeFileName files
	    testTypes = map getTestSig fName :: [String]
	    tts = zip testTypes recs :: [TypedTest]
	    kats = concatMap (uncurry (nistTestsToKAT_AES k)) (zip (zip testTypes recs) fName)
	return kats

-- Obtain the type of AES test, such as "ECBe" or "CBCd"
getTestSig :: FilePath -> String
getTestSig f = take 3 f ++ [last (dropExtension f)]

sigToF :: BlockCipher k => String -> Maybe (k -> IV k -> B.ByteString ->  (B.ByteString, IV k))
sigToF "CBCe" = Just cbc'
sigToF "CBCd" = Just unCbc'
sigToF "OFBe" = Just ofb'
sigToF "OFBd" = Just unOfb'
sigToF _ = Nothing

isEnc :: String -> Bool
isEnc str | null str = False
	  | last str == 'e' = True
	  | otherwise = False

funcAndBool x = (sigToF x, isEnc x)

nistTestsToKAT_AES :: BlockCipher k => k -> TypedTest -> String -> [KAT B.ByteString B.ByteString]
nistTestsToKAT_AES eK ("ECBe", tests) n =
	let ks = map testToKAT tests
	in concatMap maybeToList ks
  where
  testToKAT t = testToKatBasic t encryptBlock True eK n

nistTestsToKAT_AES eK ("ECBd", tests) n =
	let ks = map testToKAT tests
	in concatMap maybeToList ks
  where
  testToKAT t = testToKatBasic t decryptBlock False eK n

nistTestsToKAT_AES ek (funcAndBool -> (Just modeFunc,enc), tests) n =
	let ks = map testToKAT tests
	in concatMap maybeToList ks
  where
  testToKAT t = do
	Right iv <- liftM (Ser.decode . hexStringToBS) (lookup "IV" t)
	testToKatBasic t ((\i k -> fst . modeFunc k i) iv) enc ek n

nistTestsToKAT_AES eK _ _ = [] -- FIXME add CTR, OFB, GCM and other modes

testToKatBasic t f enc ek name = do
	cnt <- lookup "COUNT" t
	ct <- lookup "CIPHERTEXT" t
	pt <- lookup "PLAINTEXT" t
	k  <- lookup "KEY" t
	let realKey = (fromJust . buildKey . hexStringToBS $ k) `asTypeOf` ek
	    ctBS = hexStringToBS ct
	    ptBS = hexStringToBS pt
	if enc
	    then return (K ptBS (f realKey) ctBS (name ++ "-" ++ cnt))
	    else return (K ctBS (f realKey) ptBS (name ++ "-" ++ cnt))

md5KATs :: Hash c d => d -> [KAT L.ByteString d]
md5KATs d =
	[ K "" hash (toD d "d41d8cd98f00b204e9800998ecf8427e") "md5KAT1"
	, K "a" hash (toD d "0cc175b9c0f1b6a831c399e269772661") "md5KAT2"
        , K "abc" hash (toD d "900150983cd24fb0d6963f7d28e17f72") "md5KAT3"
	, K "message digest" hash (toD d "f96b697d7cb7938d525a2f31aaf161d0") "md5KAT4"
	, K "abcdefghijklmnopqrstuvwxyz" hash (toD d "c3fcd3d76192e4007dfb496cca67e13b") "md5KAT5"
	, K "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" hash (toD d "d174ab98d277d9f5a5611c2c9f419d9f") "md5KAT6"
	, K "12345678901234567890123456789012345678901234567890123456789012345678901234567890" hash (toD d "57edf4a22be3c955ac49da2e2107b67a") "md5KAT7"
	]

sha1KATs d =
	[ K "" hash (toD d "da39a3ee5e6b4b0d3255bfef95601890afd80709") "sha1KAT1"
	, K dogStr hash (toD d "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") "sha1KAT2"
	, K cogStr hash (toD d "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3") "sha1KAT3"
	]
sha224KATs d =
	[ K "" hash (toD d "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f") "sha224KAT1"
	, K dogStr hash (toD d "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525") "sha224KAT2"
	, K cogStr hash (toD d "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b") "sha224KAT3"
	]
sha256KATs d =
	[ K "" hash (toD d "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") "sha256KAT1"
	, K dogStr hash
	  (toD d "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592") "sha256KAT2"
	, K cogStr hash
	  (toD d "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be") "sha256KAT3"
	]
sha384KATs d =
	[ K "" hash
	  (toD d "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b") "sha384KAT1"
	, K dogStr hash
	  (toD d "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1") "sha384KAT2"
	, K cogStr hash
	  (toD d "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b") "sha384KAT3"
	]
sha512KATs d =
	[ K "" hash (toD d $ "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a92"
	            ++ "1d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417"
		    ++ "a81a538327af927da3e") "sha512KAT1"
	, K dogStr hash (toD d $ "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a30"
	            ++ "9d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097"
	            ++ "821233fa0538f3db854fee6") "sha512KAT2"
	, K cogStr hash (toD d $ "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1"
		    ++ "a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4"
		    ++ "cc8dfcab7da11c8ae5045") "sha512KAT3"
	]

-- |Generic routine to construct a series of tests for any hash.  Used by the 'make[SHA,MD5]Tests routines.
makeHashTests :: Hash c d => (d -> [KAT L.ByteString d]) -> d -> [Test]
makeHashTests k d = map katToTest (k d) ++ makeHashPropTests d

makeMD5Tests :: Hash c d => d -> [Test]
makeMD5Tests = makeHashTests md5KATs

makeSHA1Tests :: Hash c d => d -> [Test]
makeSHA1Tests = makeHashTests sha1KATs

makeSHA224Tests :: Hash c d => d -> [Test]
makeSHA224Tests = makeHashTests sha224KATs

makeSHA256Tests :: Hash c d => d -> [Test]
makeSHA256Tests = makeHashTests sha256KATs

makeSHA384Tests :: Hash c d => d -> [Test]
makeSHA384Tests = makeHashTests sha384KATs

makeSHA512Tests :: Hash c d => d -> [Test]
makeSHA512Tests = makeHashTests sha512KATs

-- |Based on NIST KATs, build a list 
-- of Tests for the instantiated AES
-- algorithm.
makeAESTests :: BlockCipher k => k -> IO [Test]
makeAESTests k = do
	kats <- getAES_KATs k
	return (map katToTest kats ++ makeBlockCipherPropTests k)

-- |Run a single test
runTest :: Test -> IO ()
runTest (T a s) = do
    putStr ("prop_" ++ s ++ ": ")
    quickCheck a
runTest (TK b s) = putStrLn ("kat_" ++ s ++ ": " ++ show b)

-- |Run a list of tests
runTests :: [Test] -> IO ()
runTests = mapM_ runTest
