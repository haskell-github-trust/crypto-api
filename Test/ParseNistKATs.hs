-- |
-- Maintainer: Thomas.DuBuisson@gmail.com
-- Stability: beta
-- Portability: portable 
--
--
-- NIST KAT files are composed of properties, such as:
--
-- >	[SHA-1]
-- >	[PredictionResistance = True]
-- >	[EntropyInputSize = 128]
--
-- and individual known answer tests using these properties, ex:
--
-- >	COUNT = 0
-- >	EntropyInput = 7
-- >	PersonalizationString =
-- >	Result = 8
-- >
-- >	COUNT = 1
-- >	EntropyInput = 4
-- >	PersonalizationString = 
-- >	Result = 2
--
-- Using 'many parseCategory' this input would be converted to a
-- single element list of 'TestCategory':
--
-- >	[([("SHA-1",""), ("PredictionResistance", "True"), ("EntropyInputSize", "128")],
-- >	  	[   [("COUNT", "0"), ("EntropyInput", "7"), ("PersonalizationString", ""), ("Result", "8")], 
-- >		  , [("COUNT", "1"), ("EntropyInput", "4"), ("PersonalizationString", ""), ("Result", "2")]])]
--
-- that is, a list of tuples, the first element is a list of properties (key/value pairs) and
-- the second element is a list of tests.  Each test is itself a list of records (key/value pairs).
-- Properties apply to all tests contained in the second element of the tuple.
module Test.ParseNistKATs
	( parseCategories --, parseCategory, parseProperty
	, Properties, Record, NistTest, TypedTest, TestCategory
	) where

import Data.Char (isSpace)
import Data.Maybe (listToMaybe)
import Control.Arrow (second)

type Properties = [(String, String)]
type Record = (String, String)
type NistTest = [Record]
type TypedTest = (String, [NistTest])

type TestCategory = (Properties, [NistTest])

parseCategories :: String -> String -> [(Properties, [NistTest])]
parseCategories delim file =
	getCategories delim . elimWhite . elimComments . lines $ file

elimComments = filter ((/= Just '#') . listToMaybe)
elimWhite = map (filter (/= '\r')) . filter (notNull . filter (not . isSpace))
getCategories :: String -> [String] -> [(Properties, [NistTest])]
getCategories _ [] = []
getCategories delim ls =
	let (tt, rest) = getCategory delim ls
	in tt : getCategories delim rest
getCategory delim ls =
	let (props,rest1) = break ((/= Just '[') . listToMaybe) ls
	    (tests,rest2) = break ((== Just '[') . listToMaybe) rest1
	in ((map parseProp props, parseTests delim tests), rest2)
parseProp = second (drop 1) . break (== '=') . filter (`notElem` "[]")
parseTests :: String -> [String] -> [NistTest]
parseTests delim = filter notNull . chunk ((== delim) . fst) . map parseRecord
parseRecord = second (drop 1) . break (== '=') . filter (not . isSpace)
notNull = not . null

chunk :: (a -> Bool) -> [a] -> [[a]]
chunk f xs = snd (go xs)
  where
  go [] = ([],[])
  go (a:as) = if f a
		then let (t,ts) = go as in ([], (a:t):ts)
		else let (t, ts) = go as
		     in (a:t, ts)
