{-# LANGUAGE ViewPatterns #-}
module Test.AES
	( makeAESTests
	) where

import Control.Monad (forM, liftM, filterM)
import Crypto.Classes
import Crypto.Modes
import qualified Data.ByteString as B
import qualified Data.Serialize as Ser
import Data.List (isInfixOf)
import Data.Maybe (fromJust, maybeToList)
import Paths_crypto_api
import System.Directory (getDirectoryContents, doesFileExist)
import System.FilePath (takeFileName, combine, dropExtension, (</>))
import Test.Crypto
import Test.ParseNistKATs

-- |Based on NIST KATs, build a list  of Tests for the instantiated AES algorithm.
makeAESTests :: BlockCipher k => k -> IO [Test]
makeAESTests k = do
        kats <- getAES_KATs k
        return (kats ++ makeBlockCipherPropTests k)

getAES_KATs :: BlockCipher k => k -> IO [Test]
getAES_KATs k = do
        dataDir <- getDataFileName ("Test" </> "KAT_AES")
        filesAndDirs <- getDirectoryContents dataDir
        files <- filterM doesFileExist (map (combine dataDir) filesAndDirs)
        recEs <- mapM (liftM (parseCategories "COUNT") . readFile) files :: IO [[(Properties, [NistTest])]]
        let recs = map snd (concat recEs)
            fName = map takeFileName files
            testTypes = map getTestSig fName :: [String]
            tts = zip testTypes recs :: [TypedTest]
            kats = concatMap (uncurry (nistTestsToKAT_AES k)) (zip (zip testTypes recs) fName)
        return kats
  where
  -- Obtain the type of AES test, such as "ECBe" or "CBCd"
  getTestSig :: FilePath -> String
  getTestSig f =
	let sig = take 3 f ++ [last (dropExtension f)]
	in if "CFB" `isInfixOf` sig && not ("CFB128" `isInfixOf` f)
		then "THIS IS NOT A SUPPORTED CIPHER"
		else sig

-- convert the NIST KATs to a list of KAT data types.
nistTestsToKAT_AES :: BlockCipher k => k -> TypedTest -> String -> [Test]
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

nistTestsToKAT_AES eK _ _ = [] 

-- Boiler plate code leveraged by each case of nistTestsToKAT
testToKatBasic t f enc ek name = do
        cnt <- lookup "COUNT" t
        ct <- lookup "CIPHERTEXT" t
        pt <- lookup "PLAINTEXT" t
        k  <- lookup "KEY" t
        let realKey = (fromJust . buildKey . hexStringToBS $ k) `asTypeOf` ek
            ctBS = hexStringToBS ct
            ptBS = hexStringToBS pt
	    nm   = name ++ "-" ++ cnt
        if enc
            then return (TK (f realKey ptBS == ctBS) nm)
            else return (TK (f realKey ctBS == ptBS) nm)

isEnc :: String -> Bool
isEnc str | null str = False
          | last str == 'e' = True
          | otherwise = False

-- Based o nthe name of the KAT file
-- obtain the mode function and a boolean indicating if the test is
-- for encryption (True) or decryption (False).
funcAndBool x = (sigToF x, isEnc x)
  where
  sigToF :: BlockCipher k => String -> Maybe (k -> IV k -> B.ByteString ->  (B.ByteString, IV k))
  sigToF "CBCe" = Just cbc'
  sigToF "CBCd" = Just unCbc'
  sigToF "OFBe" = Just ofb'
  sigToF "OFBd" = Just unOfb'
  sigToF "CFBe" = Just cfb'
  sigToF "CFBd" = Just unCfb'
  sigToF _ = Nothing


