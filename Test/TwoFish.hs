module Test.TwoFish
        ( makeTwoFishTests
        ) where

import Data.Maybe (fromJust)
import Data.Maybe (maybeToList)
import qualified Data.ByteString as B
import Crypto.Classes
import Crypto.Modes
import qualified Data.Serialize as Ser
import Test.Crypto
import Control.Monad (forM, liftM, filterM)
import Test.ParseNistKATs
import System.Directory (getDirectoryContents, doesFileExist)
import System.FilePath (takeFileName, combine, dropExtension, (</>))
import Paths_crypto_api

makeTwoFishTests :: BlockCipher k => k -> IO [Test]
makeTwoFishTests k = do
	kats <- getKATs k
	return (kats ++ makeBlockCipherPropTests k)

getKATs :: BlockCipher k => k -> IO [Test]
getKATs k = do
	dataDir <- getDataFileName ("Test" </> "KAT_TWOFISH")
	filesAndDirs <- getDirectoryContents dataDir
	files <- filterM doesFileExist (map (combine dataDir) filesAndDirs) :: IO [FilePath]
	recEs <- mapM (liftM (parseCategories "I") . readFile) files :: IO [[(Properties, [NistTest])]]
	let testConst = map (buildTestFunc k . dropExtension . takeFileName) files :: [(Properties, [Record]) -> Maybe Test]
	    nistTests = map (concatMap (\(p,rs) -> map (\r -> (p,r)) rs)) recEs :: [[(Properties,NistTest)]]
	    tests = zipWith (\f t -> concatMap (maybeToList . f) t) testConst nistTests
	return (concat tests)

buildTestFunc :: BlockCipher k => k -> String -> (Properties,[Record]) -> Maybe Test
buildTestFunc u "CBC_D_M" (_,rs) = do
	k <- lookupB "KEY" rs
	Right iv <- liftM Ser.decode (lookupB "IV" rs)
	ct <- lookupB "CT" rs
	pt <- lookupB "PT" rs
	i  <- lookup "I" rs
	let k' = toKey k u
	return $ TK (fst (unCbc' k' iv ct) == pt) ("CBC-D-" ++ i)
buildTestFunc u "CBC_E_M" (_,rs) = do
	k <- lookupB "KEY" rs
	Right iv <- liftM Ser.decode (lookupB "IV" rs)
	ct <- lookupB "CT" rs
	pt <- lookupB "PT" rs
	i  <- lookup "I" rs
	let k' = toKey k u
	return $ TK (fst (cbc' k' iv pt) == ct) ("CBC-E-" ++ i)
buildTestFunc u "ECB_D_M" (_,rs) = buildTestBasic u "ECB-D" rs False unEcb'
buildTestFunc u "ECB_E_M" (_,rs) = buildTestBasic u "ECB-E" rs True  ecb'
buildTestFunc u "ECB_TLB" (_,rs) = (buildTestBasic u "ECB-TLB-E" rs True ecb')
buildTestFunc u "ECB_VK" (ps,rs)  = do
	pt <- lookupB "PT" ps
	k  <- lookupB "KEY" rs
	ct <- lookupB "CT" rs
	let k' = toKey k u
	i <- lookup "I" rs
	return $ TK (ecb' k' pt == ct) ("ECB-E-VK" ++ i)
buildTestFunc u "ECB_VT" (ps,rs)  = do
	k <- lookupB "KEY" ps
	pt <- lookupB "PT" rs
	ct <- lookupB "CT" rs
	let k' = toKey k u
	i <- lookup "I" rs
	return $ TK (ecb' k' pt == ct) ("ECB-E-VT-" ++ i)

buildTestBasic :: BlockCipher k => k -> String -> [Record] -> Bool -> (k -> B.ByteString -> B.ByteString) -> Maybe Test
buildTestBasic u name rs b func = do
	k <- lookupB "KEY" rs
	c <- lookupB "CT" rs
	p <- lookupB "PT" rs
	i <- lookup "I" rs
	let k' = toKey k u
	    (x,y) = if b then (p,c) else (c,p)
	return $ TK (func k' x == y) (name ++ "-" ++ i)

lookupB :: String -> [Record] -> Maybe B.ByteString
lookupB s = liftM hexStringToBS . lookup s

toKey :: BlockCipher k => B.ByteString -> k -> k
toKey bs _ = fromJust (buildKey bs)
