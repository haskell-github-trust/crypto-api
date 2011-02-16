{-# LANGUAGE OverloadedStrings, ExistentialQuantification, ViewPatterns #-}
{- |
  Maintainer: Thomas.DuBuisson@gmail.com
  Stability: beta
  Portability: portable 


  Basic tests for some common cryptographic algorithms
  Most user only need to run the {make,run}Tests functions:

@        runTests (makeMD5Tests (undefined :: MD5Digest))
@
 
   or
  
@       runTests =<< makeAESTests (undefined :: AESKey)
@
 
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
	-- * Block Cipher KATs
	, makeBlockCipherPropTests
	-- * Hash property tests
	, makeHashPropTests
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
import Crypto.Padding
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString as B
import Control.Monad (forM)
import qualified Data.Serialize as Ser
import Numeric (readHex)
import Control.Arrow (first,second)

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
	h = L.fromChunks [Ser.encode $ f lps]
	h' = Ser.encode . f' . B.concat . L.toChunks $ lps
	o = (outputLength `for` d) `div` 8

-- |Verify the Serilize and Binary (decode . encode = id)
prop_GetPutHash :: Hash c d => d -> L.ByteString -> Bool
prop_GetPutHash d lps = Ser.decode (Ser.encode h') == Right h'
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

-- |some generic blockcipher tests

goodKey :: BlockCipher k => k -> B.ByteString -> Bool
goodKey k bs =
	case (getKey k bs `asTypeOf` Just k) of
		Nothing -> False
		Just _  -> True

bKey k bs = let Just k' = (getKey k bs `asTypeOf` Just k) in k'

-- Pad out (or trim) material to correct length (for testing only!)
getKey :: BlockCipher k => k -> B.ByteString -> Maybe k
getKey k bs =
	let l  = (keyLength `for` k) `div` 8
	    b' = B.take l (B.concat $ replicate l (B.append bs (B.singleton 0)))
	in buildKey b'

bIV :: BlockCipher k => k -> B.ByteString -> Either String (IV k)
bIV k bs = Ser.decode bs

isRight (Right _) = True
isRight (Left _)  = False

comparePadded :: BlockCipher k => k -> (k -> B.ByteString -> B.ByteString) -> (k -> B.ByteString -> B.ByteString) -> B.ByteString -> Bool
comparePadded k enc dec msg = unpadESP (dec k (enc k (padESPBlockSize k msg))) == Just msg

prop_ECBEncDecID :: BlockCipher k => k -> B.ByteString -> B.ByteString -> Property
prop_ECBEncDecID k kBS msg = goodKey k kBS ==>
	let key = bKey k kBS
	in comparePadded key ecb' unEcb' msg

prop_CBCEncDecID :: BlockCipher k => k -> B.ByteString -> B.ByteString -> B.ByteString -> Property
prop_CBCEncDecID k kBS ivBS msg = goodKey k kBS && isRight (bIV k ivBS) ==>
	let key = bKey k kBS
	    Right iv  = bIV k ivBS
	    msg' = padESPBlockSize key msg
	    (ct,iv2) = cbc' key iv msg'
	in unCbc' key iv ct == (msg', iv2)

prop_CFBEncDecID :: BlockCipher k => k -> B.ByteString -> B.ByteString -> B.ByteString -> Property
prop_CFBEncDecID k kBS ivBS msg =  goodKey k kBS && isRight (bIV k ivBS) ==>
        let key = bKey k kBS
            Right iv  = bIV k ivBS
            msg' = padESPBlockSize key msg
            (ct,iv2) = cfb' key iv msg'
	in unCfb' key iv ct == (msg', iv2)

prop_OFBEncDecID ::  BlockCipher k => k -> B.ByteString -> B.ByteString -> B.ByteString -> Property
prop_OFBEncDecID k kBS ivBS msg =  goodKey k kBS && isRight (bIV k ivBS) ==>
        let key = bKey k kBS
            Right iv  = bIV k ivBS
            msg' = padESPBlockSize key msg
            (ct,iv2) = ofb' key iv msg'
        in unOfb' key iv ct == (msg', iv2)

takeBlockSize :: BlockCipher k => k -> L.ByteString -> L.ByteString
takeBlockSize k bs = L.take (len - (len `rem` bLen)) bs
  where
  len = L.length bs
  bLen = fromIntegral $ blockSizeBytes `for` k

l2b = B.concat . L.toChunks

prop_OFBStrictLazyEq :: BlockCipher k => k -> B.ByteString -> B.ByteString -> L.ByteString -> Property
prop_OFBStrictLazyEq k kBS ivBS msg = goodKey k kBS && isRight (bIV k ivBS) ==>
	let key = bKey k kBS
	    Right iv = bIV k ivBS
	    msg' = takeBlockSize k msg
	    ctStrict = ofb' key iv (l2b msg')
	    ctLazy   = ofb  key iv msg'
	    ptStrict = unOfb' key iv (l2b msg')
	    ptLazy   = unOfb key iv msg'
	in ctStrict == first l2b ctLazy && ptStrict == first l2b ptLazy

prop_CBCStrictLazyEq :: BlockCipher k => k -> B.ByteString -> B.ByteString -> L.ByteString -> Property
prop_CBCStrictLazyEq k kBS ivBS msg = goodKey k kBS && isRight (bIV k ivBS) ==>
	let key = bKey k kBS
	    Right iv = bIV k ivBS
	    msg' = takeBlockSize k msg
	    ctStrict = cbc' key iv (l2b msg')
	    ctLazy   = cbc  key iv msg'
	    ptStrict = unCbc' key iv (l2b msg')
	    ptLazy   = unCbc key iv msg'
	in ctStrict == first l2b ctLazy && ptStrict == first l2b ptLazy

prop_CFBStrictLazyEq :: BlockCipher k => k -> B.ByteString -> B.ByteString -> L.ByteString -> Property
prop_CFBStrictLazyEq k kBS ivBS msg = goodKey k kBS && isRight (bIV k ivBS) ==>
	let key = bKey k kBS
	    Right iv = bIV k ivBS
	    msg' = takeBlockSize k msg
	    ctStrict = ofb' key iv (l2b msg')
	    ctLazy   = ofb  key iv msg'
	    ptStrict = unCfb' key iv (l2b msg')
	    ptLazy   = unCfb key iv msg'
	in ctStrict == first l2b ctLazy && ptStrict == first l2b ptLazy

prop_ECBStrictLazyEq :: BlockCipher k => k -> B.ByteString -> L.ByteString -> Property
prop_ECBStrictLazyEq k kBS msg = goodKey k kBS ==>
	let key = bKey k kBS
	    msg' = takeBlockSize k msg
	    ctStrict = ecb' key (l2b msg')
	    ctLazy   = ecb  key msg'
	    ptStrict = unEcb' key (l2b msg')
	    ptLazy   = unEcb key msg'
	in ctStrict == l2b ctLazy && ptStrict == l2b ptLazy

makeBlockCipherPropTests :: BlockCipher k => k -> [Test]
makeBlockCipherPropTests k =
	[ T (prop_ECBEncDecID k) "ECBEncDecID"
	, T (prop_CBCEncDecID k) "CBCEncDecID"
	, T (prop_CFBEncDecID k) "CFBEncDecID"
	, T (prop_OFBEncDecID k) "CFBEncDecID"
	, T (prop_ECBStrictLazyEq k) "ECBStrictLazyEq"
	, T (prop_CBCStrictLazyEq k) "CBCStrictLazyEq"
	, T (prop_CFBStrictLazyEq k) "CFBStrictLazyEq"
	, T (prop_OFBStrictLazyEq k) "OFBStrictLazyEq"
	]

data KAT i o = K i (i -> o) o String

runKATs :: (Eq o) => [KAT i o] -> Bool
runKATs = all goodKAT
  where
  goodKAT (K i f o _) = f i == o

-- *Known Answer Tests
toD :: Hash c d => d -> String -> d
toD d str = (fromRight . Ser.decode . hexStringToBS $ str) `asTypeOf` d
  where
  fromRight (Right x) = x

-- |Convert hex strings to bytestrings, for example:
-- 
-- > "3adf91c0" ==> B.pack [0x3a, 0xdf, 0x91, 0xc0]
--
-- Strings of odd length will cause an exception as will non-hex characters such as '0x'.
hexStringToBS :: String -> B.ByteString
hexStringToBS [] = B.empty
hexStringToBS (_:[]) = error "Not an even number of hex characters in input to hexStringToBS!"
hexStringToBS (a:b:xs) = B.cons (rHex (a:b:[])) (hexStringToBS xs)
  where
  rHex = fst . head . readHex

dogStr = "The quick brown fox jumps over the lazy dog"
cogStr = "The quick brown fox jumps over the lazy cog"

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

-- |Generic routine to construct a series of tests for any hash.  Used by the 'make[SHA,MD5]Tests routines.
makeHashTests :: Hash c d => (d -> [KAT L.ByteString d]) -> d -> [Test]
makeHashTests k d = map katToTest (k d) ++ makeHashPropTests d

makeMD5Tests :: Hash c d => d -> [Test]
makeMD5Tests = makeHashTests md5KATs

-- |Run a single test
runTest :: Test -> IO ()
runTest (T a s) = do
    putStr ("prop_" ++ s ++ ": ")
    quickCheck a
runTest (TK b s) = putStrLn ("kat_" ++ s ++ ": " ++ show b)

-- |Run a list of tests
runTests :: [Test] -> IO ()
runTests = mapM_ runTest
