module Test.HMAC
	( makeSHA1HMACTests
	, makeSHA224HMACTests
	, makeSHA256HMACTests
	, makeSHA384HMACTests
	, makeSHA512HMACTests
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
import Crypto.HMAC

makeSHA1HMACTests :: Hash c d => d -> IO [Test]
makeSHA1HMACTests d = getTests d "SHA1"

makeSHA224HMACTests :: Hash c d => d -> IO [Test]
makeSHA224HMACTests d = getTests d "SHA224"

makeSHA256HMACTests :: Hash c d => d -> IO [Test]
makeSHA256HMACTests d = getTests d "SHA256"

makeSHA384HMACTests :: Hash c d => d -> IO [Test]
makeSHA384HMACTests d = getTests d "SHA384"

makeSHA512HMACTests :: Hash c d => d -> IO [Test]
makeSHA512HMACTests d = getTests d "SHA512"

getTests :: Hash c d => d -> String -> IO [Test]
getTests d alg = do
        dataDir <- getDataFileName ("Test" </> "KAT_HMAC")
        filesAndDirs <- getDirectoryContents dataDir
        files <- filterM doesFileExist (map (combine dataDir) filesAndDirs)
        recEs <- mapM (liftM (parseCategories "Count") . readFile) files -- A list of pairs :: (property, [NistTest])
        let l = algToLen alg
            testsForAlg = filter (isLen l . fst) (concat recEs)
            nistTests = concatMap snd testsForAlg :: [NistTest]
            katPairs = concatMap (maybeToList . nistTestToPairs) nistTests
            strict k m t = B.take t $ encode (hmac' (MacKey k) m `asTypeOf` d)
            lazy   k m t = B.take t $ encode (hmac (MacKey k) m `asTypeOf` d)
            name i = "NistHMAC" ++ alg ++ "-" ++ (show i)
            chunkify bs = if B.length bs == 0 then [] else let (a,b) = B.splitAt 37 bs in a : chunkify b
            toLazy = L.fromChunks . chunkify
            tests = [TK (strict key msg tl == mac && lazy key (toLazy msg) tl == mac) (name i) | (key,msg,mac,i,tl) <- katPairs]
        return tests
  where
  isLen :: String -> Properties -> Bool
  isLen l mp =
	case lookup "L" mp of
		Nothing -> False
		Just x  -> x == l

nistTestToPairs :: NistTest -> Maybe (B.ByteString, B.ByteString, B.ByteString,String, Int)
nistTestToPairs nt = do
	msg <- lookup "Msg" nt
	key <- lookup "Key" nt
	mac <- lookup "Mac" nt
	cnt <- lookup "Count" nt
	tlen <- lookup "Tlen" nt
	let [msg', key', mac'] = map hexStringToBS [msg, key, mac]
	return (key', msg', mac', cnt, read tlen)

algToLen :: String -> String
algToLen "SHA1" = "20"
algToLen "SHA224" = "28"
algToLen "SHA256" = "32"
algToLen "SHA384" = "48"
algToLen "SHA512" = "64"
