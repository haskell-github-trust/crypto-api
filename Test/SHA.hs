{-# LANGUAGE ParallelListComp #-}
module Test.SHA
	( makeSHA1Tests
	, makeSHA224Tests
	, makeSHA256Tests
	, makeSHA384Tests
	, makeSHA512Tests
	) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Maybe (maybeToList)
import Data.List (isPrefixOf)
import Data.Serialize (encode)
import Crypto.Classes
import Control.Monad (filterM, liftM)
import Test.Crypto
import Test.ParseNistKATs
import System.Directory (getDirectoryContents, doesFileExist)
import System.FilePath (takeFileName, combine, (</>))
import Paths_crypto_api

makeSHA1Tests :: Hash c d => d -> IO [Test]
makeSHA1Tests d = liftM (++ makeHashPropTests d) (getTests d "SHA1")

makeSHA224Tests :: Hash c d => d -> IO [Test]
makeSHA224Tests d = liftM (++ makeHashPropTests d) (getTests d "SHA224")

makeSHA256Tests :: Hash c d => d -> IO [Test]
makeSHA256Tests d = liftM (++ makeHashPropTests d) (getTests d "SHA256")

makeSHA384Tests :: Hash c d => d -> IO [Test]
makeSHA384Tests d = liftM (++ makeHashPropTests d) (getTests d "SHA384")

makeSHA512Tests :: Hash c d => d -> IO [Test]
makeSHA512Tests d = liftM (++ makeHashPropTests d) (getTests d "SHA512")

getTests :: Hash c d => d -> String -> IO [Test]
getTests d prefix = do
	dataDir <- getDataFileName ("Test" </> "KAT_SHA")
	filesAndDirs <- getDirectoryContents dataDir
	files <- filterM doesFileExist (map (combine dataDir) filesAndDirs)
	let interestingFiles = filter ((prefix `isPrefixOf`) . takeFileName) files
	recEs <- mapM (liftM (parseCategories "Len") . readFile) interestingFiles
	let nistTests = concatMap snd (concat recEs) :: [NistTest]
	    katPairs = concatMap (maybeToList . hashNistTestToPairs) nistTests
	    strict = encode . hashFunc' d
	    lazy   = encode . hashFunc d
	    name i = "Nist" ++ prefix ++ "-" ++ (show i)
	    chunkify bs = if B.length bs == 0 then [] else let (a,b) = B.splitAt 37 bs in a : chunkify b
	    toLazy = L.fromChunks . chunkify
	    tests = [TK (strict msg == md && lazy (toLazy msg) == md) (name cnt) | (msg,md) <- katPairs | cnt <- [1..]]
	return tests

hashNistTestToPairs :: NistTest -> Maybe (B.ByteString,B.ByteString)
hashNistTestToPairs nt = do
	msg <- lookup "Msg" nt
	md  <- lookup "MD" nt
	len <- liftM (flip div 8 . read) (lookup "Len" nt)
	return (B.take len (hexStringToBS msg), hexStringToBS md)
